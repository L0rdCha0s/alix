#!/usr/bin/env python3
"""Structural regressions for interrupt-driven, window-scaled downloads."""

from pathlib import Path
import re
import sys


ROOT = Path(__file__).resolve().parents[1]


def source(path: str) -> str:
    return (ROOT / path).read_text(encoding="utf-8")


def require(text: str, fragment: str, message: str) -> None:
    if fragment not in text:
        raise AssertionError(message)


def macro(text: str, name: str) -> str:
    match = re.search(
        rf"^\s*#define\s+{re.escape(name)}\s+([^\s/]+)",
        text,
        re.MULTILINE,
    )
    if not match:
        raise AssertionError(f"missing macro {name}")
    return match.group(1)


def main() -> int:
    pci = source("src/drivers/pci.c")
    igb = source("src/drivers/igb.c")
    tcp = source("src/net/tcp.c")
    wget = source("src/sbin/cmd_wget.c")
    dns_header = source("include/net/dns.h")
    dns = source("src/net/dns.c")
    ntpdate = source("src/sbin/cmd_ntpdate.c")
    vfs = source("src/kernel/vfs.c")
    vfs_internal = source("src/kernel/vfs_internal.h")
    makefile = source("Makefile")

    require(pci, "uint16_t status = pci_config_read16(dev, 0x06);",
            "PCI capability discovery must inspect the full Status register")
    if ">> 8" in pci[pci.find("static uint8_t pci_find_capability"):
                         pci.find("bool pci_enable_msi")]:
        raise AssertionError("PCI capability discovery still shifts away Status bit 4")

    expected_registers = {
        "IGB_REG_ICR": "0x000C0",
        "IGB_REG_ICS": "0x000C8",
        "IGB_REG_IMS": "0x000D0",
        "IGB_REG_IMC": "0x000D8",
        "IGB_REG_IAM": "0x000E0",
    }
    for name, value in expected_registers.items():
        if macro(igb, name) != value:
            raise AssertionError(f"{name} must use the QEMU/82576 alias {value}")
    require(igb, "IGB_IMS_RXDW | IGB_IMS_RXO | IGB_IMS_RXDMT0",
            "IGB RX interrupt mask is incomplete")
    require(igb, "#define IGB_RX_DESC_COUNT 256",
            "IGB receive ring is too small for the scaled TCP window")
    require(igb, "uint32_t interval = freq / 10U;",
            "IGB watchdog must not be the 100 Hz receive fast path")

    require(tcp, "#define NET_TCP_LOCAL_WINDOW_SCALE    2U",
            "TCP receive window scaling is missing")
    require(tcp, "opt[5] = 3;", "TCP SYN does not emit window-scale kind")
    require(tcp, "socket->window_scaling_active = socket->peer_window_scale_seen;",
            "TCP window scaling is not negotiated")
    require(tcp, "uint32_t remote_window;",
            "TCP remote window cannot hold a scaled value")
    require(tcp, "g_tcp_ticket_serving",
            "TCP lock must retain fair ticket ordering")
    require(tcp, "wait_queue_wait_timeout(&socket->wait_queue",
            "TCP blocking reads must use a wake queue")

    require(wget, "#define WGET_CHUNK_SIZE (64U * 1024U)",
            "wget receive chunks regressed below 64 KiB")
    require(wget, "net_tcp_socket_read_blocking_timeout",
            "wget must block on TCP readiness instead of 10 ms polling")
    require(wget, 'strcmp(host_name, "gateway") == 0',
            "wget gateway target is unavailable")

    require(dns_header, "#define NET_DNS_MAX_ADDRS 8",
            "DNS results cannot retain redundant A records")
    require(dns_header, "net_dns_resolve_ipv4_all",
            "DNS multi-address resolver API is missing")
    require(dns, "dns_add_unique_addr(found_addrs, &found_addr_count, addr)",
            "DNS response parsing does not collect all A records")
    require(dns, "entry->addr_count = addr_count",
            "DNS cache does not preserve the address set")
    require(ntpdate, "net_dns_resolve_ipv4_all",
            "ntpdate does not request all pool addresses")
    require(ntpdate, "NTP_ATTEMPT_TIMEOUT_SECONDS 2ULL",
            "ntpdate failover timeout regressed")
    require(ntpdate, "server_index < server_count",
            "ntpdate does not fail over across pool members")

    if makefile.count("wget gateway:8000/build/user/") != 2:
        raise AssertionError("dl.sh must use exactly two bootstrap/archive HTTP transfers")
    require(makefile, "USER_ELF_ARCHIVE := $(USER_OBJDIR)/user-elfs.zip",
            "user ELF archive target is missing")
    require(makefile, "/tmp/user-elfs.zip",
            "download archive must bypass mounted AlixFS")

    require(vfs_internal, "uint64_t last_data_write_tick;",
            "VFS nodes do not track active writers")
    require(vfs, "VFS_ACTIVE_WRITE_GRACE_MS",
            "AlixFS writeback does not defer actively growing files")
    require(vfs, "defer_active_write",
            "active writeback deferral is not applied")

    print("network download contract test passed")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except AssertionError as error:
        print(f"network download contract test failed: {error}", file=sys.stderr)
        raise SystemExit(1)
