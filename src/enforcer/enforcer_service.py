from __future__ import annotations

import os
import signal
from typing import Any

from fastapi import Depends, FastAPI, HTTPException

from shared.contracts.enforcer_contracts import EnforcerActionRequest, EnforcerReleaseRequest
from shared.security import control_auth_configured, require_control_token
from src.enforcer.cgroups.cgroup_manager import CgroupV2Manager

app = FastAPI(title="Enforcer Service", version="0.4")

BASE = os.getenv("AISEC_CGROUP_BASE", "ai-sec")
CPU_V1 = "/sys/fs/cgroup/cpu"
MEM_V1 = "/sys/fs/cgroup/memory"


def _write(path: str, value: str) -> None:
    with open(path, "w", encoding="utf-8") as handle:
        handle.write(value)


def _parse_cpu_max(cpu_max: str) -> tuple[int, int]:
    quota_s, period_s = cpu_max.split()
    return int(quota_s), int(period_s)


def _assert_safe_target(pid: int, *, require_running: bool = True) -> None:
    if pid in {os.getpid(), os.getppid()}:
        raise HTTPException(status_code=403, detail="refusing to target the enforcer or its parent")
    if require_running and not os.path.exists(f"/proc/{pid}"):
        raise HTTPException(status_code=404, detail="pid not found")


def is_cgroup2fs(mount: str = "/sys/fs/cgroup") -> bool:
    try:
        with open("/proc/self/mounts", "r", encoding="utf-8") as handle:
            for line in handle:
                parts = line.split()
                if len(parts) >= 3 and parts[1] == mount and parts[2] == "cgroup2":
                    return True
    except OSError:
        pass
    return False


def cgv2_has_controllers(mount: str = "/sys/fs/cgroup") -> bool:
    try:
        with open(os.path.join(mount, "cgroup.controllers"), "r", encoding="utf-8") as handle:
            controllers = handle.read().strip().split()
        return "cpu" in controllers or "memory" in controllers
    except OSError:
        return False


def enforcer_engine() -> str:
    if is_cgroup2fs() and cgv2_has_controllers():
        return "cgroupv2"
    return "cgroupv1"


@app.get("/enforcer/status")
def status() -> dict[str, Any]:
    controllers = ""
    try:
        with open("/sys/fs/cgroup/cgroup.controllers", "r", encoding="utf-8") as handle:
            controllers = handle.read().strip()
    except OSError:
        pass

    return {
        "ok": True,
        "engine": enforcer_engine(),
        "control_auth_configured": control_auth_configured(),
        "v2": {"mount": "/sys/fs/cgroup", "controllers": controllers},
        "v1": {
            "cpu_mount": CPU_V1 if os.path.isdir(CPU_V1) else None,
            "mem_mount": MEM_V1 if os.path.isdir(MEM_V1) else None,
        },
        "base": BASE,
    }


def throttle_v2(pid: int, cpu_max: str | None, memory_max: int | None) -> dict[str, str]:
    manager = CgroupV2Manager(mount="/sys/fs/cgroup", base=BASE)
    cgroup_path = manager.create_for_pid(pid)
    manager.move_pid(pid, cgroup_path)
    if cpu_max:
        manager.set_cpu_max(cgroup_path, cpu_max)
    if memory_max is not None:
        manager.set_memory_max(cgroup_path, memory_max)
    return {"engine": "cgroupv2", "cgroup": cgroup_path}


def throttle_v1(pid: int, cpu_max: str | None, memory_max: int | None) -> dict[str, str]:
    if not os.path.isdir(CPU_V1) and not os.path.isdir(MEM_V1):
        raise HTTPException(status_code=500, detail="cgroup v1 mounts not available")

    result: dict[str, str] = {"engine": "cgroupv1"}

    if os.path.isdir(CPU_V1):
        cpu_cgroup = os.path.join(CPU_V1, BASE, str(pid))
        os.makedirs(cpu_cgroup, exist_ok=True)
        if cpu_max:
            quota, period = _parse_cpu_max(cpu_max)
            _write(os.path.join(cpu_cgroup, "cpu.cfs_period_us"), str(period))
            _write(os.path.join(cpu_cgroup, "cpu.cfs_quota_us"), str(quota))
        _write(os.path.join(cpu_cgroup, "tasks"), str(pid))
        result["cpu_cgroup"] = cpu_cgroup

    if os.path.isdir(MEM_V1) and memory_max is not None:
        memory_cgroup = os.path.join(MEM_V1, BASE, str(pid))
        os.makedirs(memory_cgroup, exist_ok=True)
        _write(os.path.join(memory_cgroup, "memory.limit_in_bytes"), str(memory_max))
        _write(os.path.join(memory_cgroup, "tasks"), str(pid))
        result["mem_cgroup"] = memory_cgroup

    return result


@app.post("/enforcer/action", dependencies=[Depends(require_control_token)])
def action(req: EnforcerActionRequest) -> dict[str, Any]:
    _assert_safe_target(req.pid)

    if req.action == "kill":
        try:
            os.kill(req.pid, signal.SIGKILL)
        except ProcessLookupError as exc:
            raise HTTPException(status_code=404, detail="pid not found") from exc
        except PermissionError as exc:
            raise HTTPException(status_code=403, detail="permission denied") from exc
        return {"ok": True, "action": "kill", "pid": req.pid}

    try:
        info = (
            throttle_v2(req.pid, req.cpu_max, req.memory_max)
            if enforcer_engine() == "cgroupv2"
            else throttle_v1(req.pid, req.cpu_max, req.memory_max)
        )
    except PermissionError as exc:
        raise HTTPException(status_code=403, detail="permission denied while updating cgroup") from exc
    except OSError as exc:
        raise HTTPException(status_code=500, detail=f"cgroup operation failed: {exc}") from exc

    return {"ok": True, "action": "throttle", "pid": req.pid, **info}


@app.post("/enforcer/release", dependencies=[Depends(require_control_token)])
def release(req: EnforcerReleaseRequest) -> dict[str, Any]:
    _assert_safe_target(req.pid, require_running=False)

    if enforcer_engine() == "cgroupv2":
        manager = CgroupV2Manager(mount="/sys/fs/cgroup", base=BASE)
        try:
            cgroup_path = manager.release_pid(req.pid)
        except FileNotFoundError as exc:
            raise HTTPException(status_code=404, detail="cgroup not found") from exc
        except PermissionError as exc:
            raise HTTPException(status_code=403, detail="permission denied while releasing cgroup") from exc
        return {
            "ok": True,
            "pid": req.pid,
            "released": True,
            "engine": "cgroupv2",
            "cgroup": cgroup_path,
        }

    if os.path.isdir(CPU_V1) and os.path.exists(f"/proc/{req.pid}"):
        try:
            _write(os.path.join(CPU_V1, "tasks"), str(req.pid))
        except OSError:
            pass
    if os.path.isdir(MEM_V1) and os.path.exists(f"/proc/{req.pid}"):
        try:
            _write(os.path.join(MEM_V1, "tasks"), str(req.pid))
        except OSError:
            pass

    return {"ok": True, "pid": req.pid, "released": True, "engine": "cgroupv1"}
