# Observability

The `scan()` API emits a `skilltrustops.scan` OpenTelemetry span when the optional
OpenTelemetry API is installed:

```bash
python -m pip install 'skilltrustops[observability]'
```

The library does not install or configure an exporter. Applications retain
control of their OpenTelemetry SDK, sampling, processors, and Datadog, Honeycomb,
Grafana, or other exporter configuration.

The span records rule-set version and discovered, passed, failed, and error
counts. It does not record skill contents, findings, credentials, or provider
payloads.

The same completion fields are emitted on the `skilltrustops` Python logger as a
structured `extra["skilltrustops"]` mapping. The library does not add handlers or
change the application's logging level.

For command-line automation, prefer the stable JSON or SARIF output. A scanner
error remains distinct from a failed trust check so dashboards and alerts do not
count incomplete scans as passes.
