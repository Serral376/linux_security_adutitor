"""Running services checks."""

from __future__ import annotations

from typing import List

from auditor.utils import Finding, Severity, run_command, which


# Services that are often unnecessary / increase attack surface
RISKY_SERVICES = {
    "telnet.socket": "Telnet",
    "telnet.service": "Telnet",
    "rsh.socket": "rsh",
    "rlogin.socket": "rlogin",
    "rexec.socket": "rexec",
    "vsftpd.service": "FTP (vsftpd)",
    "proftpd.service": "FTP (proftpd)",
    "nfs-server.service": "NFS Server",
    "rpcbind.service": "RPCbind",
    "avahi-daemon.service": "Avahi (mDNS)",
    "cups.service": "CUPS (если не нужен принтер)",
    "bluetooth.service": "Bluetooth",
}


def check_services() -> List[Finding]:
    findings: List[Finding] = []

    if not which("systemctl"):
        findings.append(Finding(
            check_id="SVC-000",
            title="systemctl не найден",
            severity=Severity.INFO,
            description="Система не использует systemd или systemctl недоступен.",
            category="services",
        ))
        return findings

    # Get list of running services
    rc, out, _ = run_command(["systemctl", "list-units", "--type=service", "--state=running", "--no-pager", "--no-legend"])
    running = set()
    if rc == 0 and out:
        for line in out.splitlines():
            parts = line.split()
            if parts:
                running.add(parts[0])

    # Check risky ones
    found_risky = []
    for svc, name in RISKY_SERVICES.items():
        # check if active
        rc, out, _ = run_command(["systemctl", "is-active", svc])
        if rc == 0 and out.strip() == "active":
            found_risky.append((svc, name))

    if found_risky:
        for svc, name in found_risky:
            findings.append(Finding(
                check_id="SVC-001",
                title=f"Запущен потенциально ненужный сервис: {name}",
                severity=Severity.MEDIUM,
                description=f"Сервис {svc} активен.",
                evidence=f"systemctl is-active {svc} → active",
                remediation=f"sudo systemctl disable --now {svc}",
                category="services",
            ))
    else:
        findings.append(Finding(
            check_id="SVC-001",
            title="Рискованные сервисы не запущены",
            severity=Severity.PASS,
            description="Классические опасные/ненужные сервисы не активны.",
            category="services",
        ))

    # Count running services (info)
    findings.append(Finding(
        check_id="SVC-INFO",
        title=f"Запущено сервисов: {len(running)}",
        severity=Severity.INFO,
        description="Общее количество активных unit-сервисов.",
        evidence=", ".join(sorted(list(running))[:30]),
        category="services",
    ))

    return findings
