# pyposc

Asynchronous TCP port scanner written in Python.

`pyposc` performs TCP connect scans against a single host. It resolves
hostnames (IPv4 and IPv6), scans ports concurrently with `asyncio`,
distinguishes **open / closed / filtered** results, and can optionally grab
service banners. Output is rendered with [`rich`](https://github.com/Textualize/rich).

## Requirements

- Python 3.10+
- `rich`
- `pyfiglet` (optional — only used for the ASCII-art banner)

Install everything with:

```
pip install -r requirements.txt
```

## Usage

```
python pyposc.py [target] [options]
```

If `target` and/or `--ports` are omitted, pyposc falls back to interactive
prompts, so it works both as a scriptable CLI and as a guided tool.

### Options

| Option | Description |
| --- | --- |
| `target` | Hostname or IP address to scan (IPv4/IPv6). |
| `-p`, `--ports` | Ports to scan: `80`, `22,80,443`, `1-1024`, mixed, or `-` for all. |
| `-c`, `--concurrency` | Max simultaneous connections (default: 500, capped at 2000). |
| `-t`, `--timeout` | Per-port connection timeout in seconds (default: 1.0). |
| `--banner` | Attempt to grab a service banner from open ports. |
| `--open-only` | Only display open ports. |
| `--no-art` | Suppress the ASCII-art banner. |
| `--version` | Print the version and exit. |

### Examples

```
python pyposc.py scanme.nmap.org -p 22,80,443
python pyposc.py 192.168.1.1 -p 1-1024 --banner
python pyposc.py 10.0.0.5 -p - -c 1000 -t 0.5 --open-only
python pyposc.py                       # fully interactive
```

## Changelog

###### Version 2.0
* Rewrote the engine on `asyncio` (replacing the manual thread pool) for
  far higher throughput and no thread-safety pitfalls.
* Added a proper `argparse` CLI while keeping interactive prompts as a fallback.
* Hostname resolution and IPv6 support via `getaddrinfo`.
* Now distinguishes open / closed / filtered ports instead of open-only.
* Optional service-banner grabbing (`--banner`).
* Results are sorted and rendered as a table; live progress bar during scans.
* Fixed a race condition in the open-port counter and a queue race that could
  deadlock idle threads in the previous design.
* Replaced bare `except:` blocks with targeted exception handling.

###### Version 1.3
* Added input validation on number of threads.
* Limited number of threads to a maximum of 1000.

###### Version 1.2
* Added a timer that prints how long the scan took.
* Fixed a bug where the last port in a range wasn't scanned.

###### Version 1.1
* Open ports with no resolvable service are now reported as `unknown`
  rather than treated as closed.