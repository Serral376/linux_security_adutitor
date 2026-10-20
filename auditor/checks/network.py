"""Network and listening ports checks."""

from __future__ import annotations

from typing import List

from auditor.utils import Finding, Severity, run_command, which


def check_network() -> List[Finding]:
    findings: List[Finding] = []

    # Prefer ss, fallback to netstat
    ss_path = which("ss")
    netstat_path = which("netstat")

    listening = ""
    if ss_path:
        rc, out, _ = run_command(["ss", "-tulnp"], timeout=10)
        if rc == 0:
            listening = out
    elif netstat_path:
        rc, out, _ = run_command(["netstat", "-tulnp"], timeout=10)
        if rc == 0:
            listening = out
    else:
        findings.append(Finding(
            check_id="NET-000",
            title="Не найдены ss/netstat",
            severity=Severity.INFO,
            description="Невозможно получить список слушающих портов.",
            category="network",
        ))
        return findings

    # Parse listening ports
    risky_ports = {
        "21": ("FTP", Severity.HIGH),
        "23": ("Telnet", Severity.CRITICAL),
        "69": ("TFTP", Severity.HIGH),
        "111": ("RPCbind", Severity.MEDIUM),
        "512": ("rexec", Severity.CRITICAL),
        "513": ("rlogin", Severity.CRITICAL),
        "514": ("rsh", Severity.CRITICAL),
        "1433": ("MSSQL", Severity.MEDIUM),
        "3306": ("MySQL", Severity.MEDIUM),
        "5432": ("PostgreSQL", Severity.MEDIUM),
        "6379": ("Redis", Severity.HIGH),
        "27017": ("MongoDB", Severity.HIGH),
        "11211": ("Memcached", Severity.HIGH),
    }

    found_risky = []
    open_ports = set()

    for line in listening.splitlines():
        line_lower = line.lower()
        if "listen" not in line_lower and "LISTEN" not in line:
            continue
        for port, (name, sev) in risky_ports.items():
            # simple match
            if f":{port} " in line or f":{port}\n" in line or line.rstrip().endswith(f":{port}"):
                found_risky.append((port, name, sev, line.strip()))
                open_ports.add(port)

    if found_risky:
        for port, name, sev, evidence in found_risky:
            findings.append(Finding(
                check_id=f"NET-{port}",
                title=f"Открыт потенциально опасный порт {port} ({name})",
                severity=sev,
                description=f"Сервис {name} слушает на порту {port}.",
                evidence=evidence,
                remediation=f"Закройте порт {port}, если сервис не нужен, или ограничьте доступ через firewall.",
                category="network",
            ))
    else:
        findings.append(Finding(
            check_id="NET-OK",
            title="Опасные порты не обнаружены",
            severity=Severity.PASS,
            description="Среди слушающих портов нет классических high-risk сервисов.",
            category="network",
        ))

    # Count total listening sockets (info)
    listen_count = sum(1 for line in listening.splitlines() if "LISTEN" in line or "listen" in line.lower())
    findings.append(Finding(
        check_id="NET-INFO",
        title=f"Всего слушающих сокетов: {listen_count}",
        severity=Severity.INFO,
        description="Общая информация о сетевой активности.",
        evidence=listening[:1500] if len(listening) > 1500 else listening,
        category="network",
    ))

    # Check if IP forwarding is enabled (router mode)
    rc, out, _ = run_command(["sysctl", "-n", "net.ipv4.ip_forward"])
    if rc == 0 and out.strip() == "1":
        findings.append(Finding(
            check_id="NET-FWD",
            title="Включён IP Forwarding",
            severity=Severity.MEDIUM,
            description="net.ipv4.ip_forward = 1. Система работает как маршрутизатор.",
            evidence="sysctl net.ipv4.ip_forward = 1",
            remediation="Если не требуется — sysctl -w net.ipv4.ip_forward=0",
            category="network",
        ))

    return findings
