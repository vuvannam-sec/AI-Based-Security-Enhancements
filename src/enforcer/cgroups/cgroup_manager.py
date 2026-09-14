from __future__ import annotations

import os


def _write(path: str, value: str) -> None:
    with open(path, "w", encoding="utf-8") as handle:
        handle.write(value)


class CgroupV2Manager:
    def __init__(self, mount: str = "/sys/fs/cgroup", base: str = "ai-sec"):
        self.mount = mount
        self.base = base
        self.base_path = os.path.join(self.mount, self.base)

    def ensure_base(self) -> None:
        """Create the delegated cgroup subtree and enable available controllers."""
        try:
            root_ctrl = os.path.join(self.mount, "cgroup.controllers")
            root_sub = os.path.join(self.mount, "cgroup.subtree_control")
            if os.path.exists(root_ctrl) and os.path.exists(root_sub):
                with open(root_ctrl, "r", encoding="utf-8") as handle:
                    controllers = handle.read().strip().split()
                wanted = [name for name in ("cpu", "memory") if name in controllers]
                if wanted:
                    _write(root_sub, " ".join(f"+{name}" for name in wanted))
        except OSError:
            pass

        os.makedirs(self.base_path, exist_ok=True)

        try:
            base_ctrl = os.path.join(self.base_path, "cgroup.controllers")
            base_sub = os.path.join(self.base_path, "cgroup.subtree_control")
            if os.path.exists(base_ctrl) and os.path.exists(base_sub):
                with open(base_ctrl, "r", encoding="utf-8") as handle:
                    controllers = handle.read().strip().split()
                wanted = [name for name in ("cpu", "memory", "pids", "io") if name in controllers]
                if wanted:
                    _write(base_sub, " ".join(f"+{name}" for name in wanted))
        except OSError:
            pass

    def path_for_pid(self, pid: int) -> str:
        return os.path.join(self.base_path, str(pid))

    def create_for_pid(self, pid: int) -> str:
        self.ensure_base()
        path = self.path_for_pid(pid)
        os.makedirs(path, exist_ok=True)
        return path

    def move_pid(self, pid: int, cgroup_path: str) -> None:
        _write(os.path.join(cgroup_path, "cgroup.procs"), str(pid))

    def set_cpu_max(self, cgroup_path: str, cpu_max: str) -> None:
        _write(os.path.join(cgroup_path, "cpu.max"), cpu_max)

    def set_memory_max(self, cgroup_path: str, memory_max: int) -> None:
        _write(os.path.join(cgroup_path, "memory.max"), str(memory_max))

    def release_pid(self, pid: int) -> str:
        """Remove resource limits while keeping the process in its managed cgroup."""
        cgroup_path = self.path_for_pid(pid)
        if not os.path.isdir(cgroup_path):
            raise FileNotFoundError(cgroup_path)

        cpu_max = os.path.join(cgroup_path, "cpu.max")
        memory_max = os.path.join(cgroup_path, "memory.max")
        if os.path.exists(cpu_max):
            _write(cpu_max, "max 100000")
        if os.path.exists(memory_max):
            _write(memory_max, "max")

        # Empty cgroups can be removed after the process exits. Do not move a live
        # process into an internal parent cgroup: that is not portable across
        # delegated/systemd-managed cgroup v2 hierarchies.
        if not os.path.exists(f"/proc/{pid}"):
            try:
                os.rmdir(cgroup_path)
            except OSError:
                pass

        return cgroup_path
