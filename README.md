# Simple Proxy for Minecraft

A small TCP proxy with an IP/CIDR whitelist. Clients that are not on the list are dropped
immediately; allowed clients are forwarded to the real Minecraft server. Pure Python 3, no dependencies.

## Run

```
python minecraft_proxy.py
```

Defaults: listen on `0.0.0.0:25565`, forward to `127.0.0.1:25566`, whitelist in `allowed_ips.json`, logs in `logs/`.

| Option | Default | Meaning |
| --- | --- | --- |
| `--listen-host` / `--listen-port` | `0.0.0.0` / `25565` | Public address |
| `--dest-host` / `--dest-port` | `127.0.0.1` / `25566` | Real server |
| `--allowed-file` | `allowed_ips.json` | JSON list of IPs or CIDR networks |
| `--log-dir` | `logs` | Log directory (previous `proxy.log` is rotated at start) |
| `--max-connections` | `200` | Concurrent proxied connections |
| `--connect-timeout` | `5` | Seconds to reach the destination |
| `--idle-timeout` | `0` | Close idle connections after N seconds (0 = never) |

## Whitelist

Copy `allowed_ips.example.json` to `allowed_ips.json` and edit it, or use the console commands:

`add <ip|cidr>`, `remove <ip|cidr>`, `list`, `reload`, `help`, `stop`.

Manual edits of the file are picked up automatically within a couple of seconds; an invalid file
keeps the previous list active. Repeated rejections from one IP are summarized once per minute
(`Attempts: N`) to keep logs small during scans.

## Log analysis

```
python log_analizer.py [LOG_FILE] [--top N]
```

Shows the top IPs by connection attempts (newest log by default). Works with old and new log formats.
