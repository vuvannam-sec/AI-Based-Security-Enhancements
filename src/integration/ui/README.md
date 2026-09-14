# Streamlit dashboard

The dashboard presents service health, recent events, detection history, and local lab controls for the Sensor and Enforcer.

Run it through the root launcher:

```bash
./scripts/run_all.sh
```

By default it is available at `http://127.0.0.1:8501`.

The UI reads `SENSOR_URL`, `ENFORCER_URL`, `ML_URL`, and `ORCH_API_URL` from the environment. Its API client also reads `AISEC_CONTROL_TOKEN` and attaches it to local control requests, allowing the dashboard to use the same authenticated control plane as the backend services.

Do not expose the dashboard as a remote administration interface without adding an appropriate authentication, TLS, and deployment layer. The built-in token is designed for local service-to-service control.
