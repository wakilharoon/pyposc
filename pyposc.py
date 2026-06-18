#!/usr/bin/env python3
"""pyposc - an asynchronous TCP port scanner.

Usage examples:
    python pyposc.py scanme.nmap.org -p 22,80,443
    python pyposc.py 192.168.1.1 -p 1-1024 --banner
    python pyposc.py 10.0.0.5 -p - -c 1000 -t 0.5
    python pyposc.py                       # interactive mode
"""

from __future__ import annotations

import argparse
import asyncio
import socket
import sys
import time
from dataclasses import dataclass
from enum import Enum

from rich.console import Console
from rich.progress import BarColumn, MofNCompleteColumn, Progress, TextColumn, TimeElapsedColumn
from rich.table import Table

try:
    from pyfiglet import Figlet

    _HAVE_FIGLET = True
except ImportError:  # pyfiglet is optional, the tool still runs without it.
    _HAVE_FIGLET = False

__version__ = "2.0"

MIN_PORT, MAX_PORT = 1, 65535
CONCURRENCY_CAP = 2000

console = Console(highlight=False)


class PortState(str, Enum):
    OPEN = "open"
    CLOSED = "closed"
    FILTERED = "filtered"


@dataclass(slots=True)
class ScanResult:
    port: int
    state: PortState
    service: str = "unknown"
    banner: str | None = None


# --------------------------------------------------------------------------- #
# Parsing / validation
# --------------------------------------------------------------------------- #
def _coerce_port(value: str) -> int:
    """Convert a string to a valid TCP port number or raise ValueError."""
    try:
        port = int(value)
    except ValueError:
        raise ValueError(f"'{value}' is not a valid port number") from None
    if not MIN_PORT <= port <= MAX_PORT:
        raise ValueError(f"port {port} is out of range ({MIN_PORT}-{MAX_PORT})")
    return port


def parse_ports(spec: str) -> list[int]:
    """Parse a port specification into a sorted, de-duplicated list.

    Accepts single ports, comma-separated lists, hyphenated ranges, and any
    combination thereof. The literals '-', 'all' and '*' expand to all ports.

        "80"            -> [80]
        "22,80,443"     -> [22, 80, 443]
        "1-1024"        -> [1, 2, ..., 1024]
        "22,80,8000-8100" -> mixed
        "-"             -> [1 .. 65535]
    """
    spec = spec.strip().lower()
    if spec in ("-", "all", "*"):
        return list(range(MIN_PORT, MAX_PORT + 1))

    ports: set[int] = set()
    for chunk in spec.split(","):
        chunk = chunk.strip()
        if not chunk:
            continue
        if "-" in chunk:
            start_s, _, end_s = chunk.partition("-")
            start, end = _coerce_port(start_s), _coerce_port(end_s)
            if start > end:
                raise ValueError(f"range '{chunk}' is reversed (start > end)")
            ports.update(range(start, end + 1))
        else:
            ports.add(_coerce_port(chunk))

    if not ports:
        raise ValueError("no valid ports specified")
    return sorted(ports)


def resolve_target(target: str) -> tuple[str, int]:
    """Resolve a hostname or IP literal to an address and socket family."""
    try:
        infos = socket.getaddrinfo(
            target, None, type=socket.SOCK_STREAM, proto=socket.IPPROTO_TCP
        )
    except socket.gaierror as exc:
        raise ValueError(f"could not resolve '{target}': {exc.strerror}") from exc
    family, _, _, _, sockaddr = infos[0]
    return sockaddr[0], family


def service_name(port: int) -> str:
    try:
        return socket.getservbyport(port, "tcp")
    except OSError:
        return "unknown"


# --------------------------------------------------------------------------- #
# Scanning
# --------------------------------------------------------------------------- #
async def scan_one(
    ip: str,
    family: int,
    port: int,
    *,
    timeout: float,
    grab_banner: bool,
    sem: asyncio.Semaphore,
    on_done,
) -> ScanResult:
    """Attempt a TCP connect to a single port and classify the result."""
    result = ScanResult(port=port, state=PortState.FILTERED)
    async with sem:
        writer = None
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host=ip, port=port, family=family),
                timeout=timeout,
            )
            result.state = PortState.OPEN
            result.service = service_name(port)
            if grab_banner:
                result.banner = await _read_banner(reader, timeout)
        except ConnectionRefusedError:
            result.state = PortState.CLOSED
        except (asyncio.TimeoutError, TimeoutError):
            result.state = PortState.FILTERED
        except OSError:
            # No route to host, network unreachable, etc.
            result.state = PortState.FILTERED
        finally:
            if writer is not None:
                writer.close()
                try:
                    await writer.wait_closed()
                except OSError:
                    pass
    on_done()
    return result


async def _read_banner(reader: asyncio.StreamReader, timeout: float) -> str | None:
    """Read a short service banner if one is offered promptly."""
    try:
        data = await asyncio.wait_for(reader.read(256), timeout=min(timeout, 2.0))
    except (asyncio.TimeoutError, TimeoutError, OSError):
        return None
    if not data:
        return None
    text = data.decode("latin-1", "replace")
    # Collapse to a single printable line.
    printable = "".join(c if c.isprintable() else " " for c in text)
    return " ".join(printable.split()) or None


async def run_scan(
    ip: str,
    family: int,
    ports: list[int],
    *,
    concurrency: int,
    timeout: float,
    grab_banner: bool,
) -> list[ScanResult]:
    sem = asyncio.Semaphore(concurrency)
    progress = Progress(
        TextColumn("[cyan]Scanning"),
        BarColumn(),
        MofNCompleteColumn(),
        TimeElapsedColumn(),
        console=console,
        transient=True,
    )
    with progress:
        task_id = progress.add_task("scan", total=len(ports))
        advance = lambda: progress.advance(task_id)  # noqa: E731
        tasks = [
            asyncio.create_task(
                scan_one(
                    ip,
                    family,
                    port,
                    timeout=timeout,
                    grab_banner=grab_banner,
                    sem=sem,
                    on_done=advance,
                )
            )
            for port in ports
        ]
        return await asyncio.gather(*tasks)


# --------------------------------------------------------------------------- #
# Presentation
# --------------------------------------------------------------------------- #
_STATE_STYLE = {
    PortState.OPEN: "green",
    PortState.CLOSED: "red",
    PortState.FILTERED: "yellow",
}


def print_banner(show_art: bool) -> None:
    if show_art and _HAVE_FIGLET:
        console.print(Figlet(font="5lineoblique").renderText("pyposc"), style="cyan")
    console.print(
        f":::> pyposc :::> async TCP port scanner :::> v2.0 :::>",
        style="yellow",
    )


def print_results(
    results: list[ScanResult],
    target: str,
    ip: str,
    elapsed: float,
    *,
    open_only: bool,
) -> None:
    counts = {state: 0 for state in PortState}
    for r in results:
        counts[r.state] += 1

    shown = [r for r in results if r.state is PortState.OPEN] if open_only else results
    shown.sort(key=lambda r: r.port)

    has_banner = any(r.banner for r in shown)

    table = Table(title=f"Results for {target} ({ip})", title_style="cyan")
    table.add_column("Port", justify="right")
    table.add_column("State")
    table.add_column("Service")
    if has_banner:
        table.add_column("Banner", overflow="fold")

    if shown:
        for r in shown:
            row = [
                str(r.port),
                f"[{_STATE_STYLE[r.state]}]{r.state.value}[/{_STATE_STYLE[r.state]}]",
                r.service,
            ]
            if has_banner:
                row.append(r.banner or "")
            table.add_row(*row)
        console.print(table)
    elif open_only:
        console.print("[yellow][!] No open ports found.[/yellow]")

    rate = len(results) / elapsed if elapsed > 0 else 0.0
    console.print(
        f"[cyan][*] Scanned {len(results)} ports in {elapsed:0.2f}s "
        f"({rate:0.0f} ports/s) - "
        f"[green]{counts[PortState.OPEN]} open[/green], "
        f"[red]{counts[PortState.CLOSED]} closed[/red], "
        f"[yellow]{counts[PortState.FILTERED]} filtered[/yellow][/cyan]"
    )


# --------------------------------------------------------------------------- #
# Interactive prompts (used when arguments are omitted)
# --------------------------------------------------------------------------- #
def prompt_target() -> tuple[str, str, int]:
    while True:
        value = console.input("\n[*] Enter target host or IP: ").strip()
        if not value:
            console.print("[red][-] Please enter a host[/red]")
            continue
        try:
            ip, family = resolve_target(value)
            return value, ip, family
        except ValueError as exc:
            console.print(f"[red][-] {exc}[/red]")


def prompt_ports() -> list[int]:
    while True:
        value = console.input(
            "[*] Enter port(s) (e.g. 80 | 22,80,443 | 1-1024 | -): "
        ).strip()
        try:
            return parse_ports(value)
        except ValueError as exc:
            console.print(f"[red][-] {exc}[/red]")


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #
def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="pyposc",
        description="Asynchronous TCP connect port scanner.",
    )
    parser.add_argument(
        "target", nargs="?", help="hostname or IP address to scan (IPv4/IPv6)"
    )
    parser.add_argument(
        "-p",
        "--ports",
        help="ports to scan: '80', '22,80,443', '1-1024', or '-' for all",
    )
    parser.add_argument(
        "-c",
        "--concurrency",
        type=int,
        default=500,
        help="max simultaneous connections (default: 500)",
    )
    parser.add_argument(
        "-t",
        "--timeout",
        type=float,
        default=1.0,
        help="per-port connection timeout in seconds (default: 1.0)",
    )
    parser.add_argument(
        "--banner", action="store_true", help="attempt to grab service banners"
    )
    parser.add_argument(
        "--open-only", action="store_true", help="only display open ports"
    )
    parser.add_argument(
        "--no-art", action="store_true", help="suppress the ASCII art banner"
    )
    parser.add_argument(
        "--version", action="version", version=f"%(prog)s {__version__}"
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    print_banner(show_art=not args.no_art)

    if args.timeout <= 0:
        console.print("[red][-] timeout must be greater than 0[/red]")
        return 1
    concurrency = max(1, min(args.concurrency, CONCURRENCY_CAP))
    if args.concurrency != concurrency:
        console.print(
            f"[yellow][!] concurrency clamped to {concurrency} "
            f"(1-{CONCURRENCY_CAP})[/yellow]"
        )

    # Resolve target.
    if args.target:
        try:
            ip, family = resolve_target(args.target)
        except ValueError as exc:
            console.print(f"[red][-] {exc}[/red]")
            return 1
        target = args.target
    else:
        target, ip, family = prompt_target()

    # Determine ports.
    if args.ports:
        try:
            ports = parse_ports(args.ports)
        except ValueError as exc:
            console.print(f"[red][-] {exc}[/red]")
            return 1
    else:
        ports = prompt_ports()

    console.print(f"\n[cyan][*] Scanning {target} ({ip}) - {len(ports)} ports[/cyan]")

    start = time.perf_counter()
    results = asyncio.run(
        run_scan(
            ip,
            family,
            ports,
            concurrency=concurrency,
            timeout=args.timeout,
            grab_banner=args.banner,
        )
    )
    elapsed = time.perf_counter() - start

    print_results(results, target, ip, elapsed, open_only=args.open_only)
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        console.print("\n[yellow][!] Interrupted[/yellow]")
        sys.exit(130)