"""File and directory permission checks."""

from __future__ import annotations

import os
from typing import List

from auditor.utils import Finding, Severity, get_file_permissions, get_owner, file_exists, run_command


CRITICAL_PATHS = [
    ("/etc/passwd", "644", "root", "root"),
    ("/etc/shadow", "640", "root", "shadow"),  # or 600 root:root
    ("/etc/group", "644", "root", "root"),
    ("/etc/gshadow", "640", "root", "shadow"),
    ("/etc/ssh/sshd_config", "600", "root", "root"),
    ("/boot/grub/grub.cfg", "600", "root", "root"),
    ("/etc/sudoers", "440", "root", "root"),
]


def check_permissions() -> List[Finding]:
    findings: List[Finding] = []

    # 1. Critical system files permissions
    for path, expected_perm, expected_user, expected_group in CRITICAL_PATHS:
        if not file_exists(path):
            continue
        perms = get_file_permissions(path)
        owner, group = get_owner(path)

        issues = []
        if perms and perms != expected_perm:
            # special case for shadow
            if path.endswith("shadow") and perms in ("600", "640"):
                pass
            else:
                issues.append(f"права {perms} (ожидается {expected_perm})")
        if owner != expected_user and not (path.endswith("shadow") and owner == "root"):
            issues.append(f"владелец {owner} (ожидается {expected_user})")

        if issues:
            severity = Severity.HIGH if "shadow" in path or "sudoers" in path else Severity.MEDIUM
            findings.append(Finding(
                check_id="PERM-001",
                title=f"Небезопасные права: {path}",
                severity=severity,
                description="; ".join(issues),
                evidence=f"{path} → {perms} {owner}:{group}",
                remediation=f"chmod {expected_perm} {path} && chown {expected_user}:{expected_group} {path}",
                category="permissions",
            ))

    # 2. World-writable files (dangerous)
    # Limit search to common places to avoid long runtime
    search_paths = ["/etc", "/usr/local/bin", "/opt", "/var/www"]
    world_writable = []
    for sp in search_paths:
        if not os.path.isdir(sp):
            continue
        rc, out, _ = run_command(
            f"find {sp} -xdev -type f -perm -0002 2>/dev/null | head -30",
            timeout=20,
        )
        if rc == 0 and out:
            world_writable.extend(out.splitlines())

    if world_writable:
        findings.append(Finding(
            check_id="PERM-002",
            title="Найдены world-writable файлы",
            severity=Severity.HIGH,
            description="Файлы, доступные на запись всем пользователям.",
            evidence="\n".join(world_writable[:15]),
            remediation="Уберите право записи для others: chmod o-w <file>",
            category="permissions",
        ))

    # 3. SUID/SGID binaries (informational + known dangerous)
    rc, out, _ = run_command(
        "find /usr /bin /sbin /opt -xdev \\( -perm -4000 -o -perm -2000 \\) -type f 2>/dev/null | head -40",
        timeout=25,
    )
    if rc == 0 and out:
        suid_files = out.splitlines()
        # Known potentially dangerous
        suspicious = [f for f in suid_files if any(x in f for x in ("nmap", "perl", "python", "find", "vim", "nano", "less", "more", "cp", "mv"))]
        findings.append(Finding(
            check_id="PERM-003",
            title=f"Найдено {len(suid_files)} SUID/SGID файлов",
            severity=Severity.INFO,
            description="Список бинарников с установленным SUID/SGID (первые 20).",
            evidence="\n".join(suid_files[:20]),
            remediation="Регулярно проверяйте SUID/SGID. Удаляйте ненужные.",
            category="permissions",
        ))
        if suspicious:
            findings.append(Finding(
                check_id="PERM-004",
                title="Подозрительные SUID-бинарники",
                severity=Severity.MEDIUM,
                description="SUID на интерпретаторах или утилитах, которые могут быть опасны.",
                evidence="\n".join(suspicious),
                remediation="Снимите SUID: chmod u-s <file>, если не требуется.",
                category="permissions",
            ))

    # 4. Home directories permissions
    try:
        import pwd
        for user in pwd.getpwall():
            if user.pw_uid >= 1000 and user.pw_dir.startswith("/home"):
                if os.path.isdir(user.pw_dir):
                    perms = get_file_permissions(user.pw_dir)
                    if perms and perms[-1] in ("7", "6", "3", "2"):  # others have write/read+write
                        findings.append(Finding(
                            check_id="PERM-005",
                            title=f"Открытая домашняя директория: {user.pw_dir}",
                            severity=Severity.MEDIUM,
                            description=f"Права {perms} — others имеют доступ.",
                            evidence=f"{user.pw_dir} → {perms}",
                            remediation=f"chmod 750 {user.pw_dir}",
                            category="permissions",
                        ))
    except Exception:
        pass

    if not any(f.severity.value not in ("pass", "info") for f in findings):
        # only if no real issues
        pass

    return findings
