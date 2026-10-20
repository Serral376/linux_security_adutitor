"""User and account security checks."""

from __future__ import annotations

import pwd
import grp
import os
from typing import List

from auditor.utils import Finding, Severity, run_command, is_root, read_file


def check_users() -> List[Finding]:
    findings: List[Finding] = []

    # 1. Users with UID 0 (besides root)
    try:
        for user in pwd.getpwall():
            if user.pw_uid == 0 and user.pw_name != "root":
                findings.append(Finding(
                    check_id="USERS-001",
                    title=f"Дополнительный пользователь с UID 0: {user.pw_name}",
                    severity=Severity.CRITICAL,
                    description="Найден пользователь с правами root (UID 0), отличный от root.",
                    evidence=f"user={user.pw_name}, uid={user.pw_uid}, shell={user.pw_shell}",
                    remediation="Удалите пользователя или измените его UID. Оставьте UID 0 только у root.",
                    category="users",
                ))
    except Exception as e:
        findings.append(Finding(
            check_id="USERS-000",
            title="Ошибка при проверке пользователей",
            severity=Severity.INFO,
            description=str(e),
            category="users",
        ))

    # 2. Users with empty password (requires root / shadow)
    if is_root() and os.path.exists("/etc/shadow"):
        shadow = read_file("/etc/shadow")
        if shadow:
            for line in shadow.splitlines():
                parts = line.split(":")
                if len(parts) >= 2:
                    username, password_hash = parts[0], parts[1]
                    if password_hash == "" or password_hash == "!" or password_hash == "*":
                        # locked accounts are ok, empty is bad
                        if password_hash == "":
                            findings.append(Finding(
                                check_id="USERS-002",
                                title=f"Пользователь без пароля: {username}",
                                severity=Severity.CRITICAL,
                                description="Учётная запись не имеет пароля.",
                                evidence=f"shadow entry: {username}:...",
                                remediation="Установите пароль или заблокируйте учётную запись (passwd -l).",
                                category="users",
                            ))
    else:
        findings.append(Finding(
            check_id="USERS-002i",
            title="Проверка пустых паролей пропущена",
            severity=Severity.INFO,
            description="Требуются права root для чтения /etc/shadow.",
            category="users",
        ))

    # 3. Users with interactive shells that shouldn't have them
    system_users_with_shell = []
    try:
        for user in pwd.getpwall():
            if user.pw_uid < 1000 and user.pw_name not in ("root",):
                if user.pw_shell not in ("/usr/sbin/nologin", "/sbin/nologin", "/bin/false", "/usr/bin/nologin"):
                    system_users_with_shell.append(f"{user.pw_name} ({user.pw_shell})")
        if system_users_with_shell:
            findings.append(Finding(
                check_id="USERS-003",
                title="Системные пользователи с интерактивной оболочкой",
                severity=Severity.MEDIUM,
                description="Системные учётные записи (UID < 1000) имеют login shell.",
                evidence=", ".join(system_users_with_shell[:10]),
                remediation="Установите /usr/sbin/nologin или /bin/false для системных пользователей.",
                category="users",
            ))
    except Exception:
        pass

    # 4. Users with UID >= 1000 that have no password aging (basic)
    # 5. sudo group members
    try:
        sudo_group = grp.getgrnam("sudo")
        members = sudo_group.gr_mem
        if members:
            findings.append(Finding(
                check_id="USERS-004",
                title="Пользователи в группе sudo",
                severity=Severity.INFO,
                description="Список пользователей, имеющих право sudo.",
                evidence=", ".join(members) if members else "нет",
                remediation="Регулярно проверяйте состав группы sudo. Используйте принцип наименьших привилегий.",
                category="users",
            ))
    except KeyError:
        # no sudo group (maybe wheel on some systems)
        try:
            wheel = grp.getgrnam("wheel")
            findings.append(Finding(
                check_id="USERS-004",
                title="Пользователи в группе wheel",
                severity=Severity.INFO,
                description="Список пользователей в группе wheel.",
                evidence=", ".join(wheel.gr_mem),
                category="users",
            ))
        except KeyError:
            pass

    # 6. Check for accounts with expired passwords or locked (basic via passwd -S if available)
    rc, out, _ = run_command(["passwd", "-S", "-a"])
    if rc == 0 and out:
        locked = []
        for line in out.splitlines():
            parts = line.split()
            if len(parts) >= 2 and parts[1] in ("L", "LK"):
                locked.append(parts[0])
        if locked:
            findings.append(Finding(
                check_id="USERS-005",
                title="Заблокированные учётные записи",
                severity=Severity.INFO,
                description="Найдены заблокированные аккаунты (это нормально, но стоит знать).",
                evidence=", ".join(locked[:15]),
                category="users",
            ))

    if not findings:
        findings.append(Finding(
            check_id="USERS-OK",
            title="Проверка пользователей пройдена",
            severity=Severity.PASS,
            description="Критических проблем с учётными записями не обнаружено.",
            category="users",
        ))

    return findings
