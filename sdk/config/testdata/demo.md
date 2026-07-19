One file per binary; every key can be overridden with its derived
environment variable. Unknown keys and unknown `PM_*` variables fail
boot [INV-18].

## [server]

| key | env override | type | default | description |
|---|---|---|---|---|
| `listen_addr` | `PM_SERVER_LISTEN_ADDR` | string | `127.0.0.1:8080` | Bind address for the demo listener. |
| `max_conns` | `PM_SERVER_MAX_CONNS` | int | `42` | Upper bound on concurrent demo connections. |
| `http_port` | `PM_SERVER_HTTP_PORT` | int | `8443` | Demo HTTPS port. |

## [log]

| key | env override | type | default | description |
|---|---|---|---|---|
| `verbose` | `PM_LOG_VERBOSE` | bool | `false` | Emit per-request demo logging. |
| `format` | `PM_LOG_FORMAT` | string | `json` | Demo log encoding. |
