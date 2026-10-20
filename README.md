# Linux Security Auditor

![Python](https://img.shields.io/badge/Python-3.10+-blue.svg)
![License](https://img.shields.io/badge/License-MIT-green.svg)
![Platform](https://img.shields.io/badge/Platform-Linux-orange.svg)

**Модульный инструмент аудита безопасности Linux-систем** средней сложности для портфолио специалиста по информационной безопасности.

Инструмент проверяет типичные проблемы безопасности, собирает findings с уровнями критичности и генерирует отчёты в Markdown и HTML.

---

## Возможности

| Модуль | Что проверяет |
|--------|---------------|
| **users** | UID 0, пустые пароли, системные аккаунты с shell, группа sudo/wheel |
| **ssh** | PermitRootLogin, PasswordAuthentication, права на ключи и sshd_config, MaxAuthTries и др. |
| **permissions** | Права критических файлов (`/etc/shadow`, `sudoers`…), world-writable, SUID/SGID |
| **network** | Слушающие порты, опасные сервисы (Telnet, Redis, MongoDB…), IP forwarding |
| **packages** | Доступные обновления (apt / dnf / pacman), unattended-upgrades |
| **services** | Запущенные рискованные сервисы (FTP, NFS, Avahi, Bluetooth…) |
| **firewall** | Статус UFW / firewalld / iptables / nftables |
| **cron** | Подозрительные задачи, world-writable директории cron |

---

## Быстрый старт

```bash
# Клонировать
git clone https://github.com/<your-username>/linux-security-auditor.git
cd linux-security-auditor

# Установить зависимости
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt

# Запуск (рекомендуется от root для полного покрытия)
sudo python3 main.py
```

### Примеры использования

```bash
# Все проверки
python3 main.py

# Только выбранные модули
python3 main.py --only users,ssh,firewall

# Подробный вывод + без сохранения отчётов
python3 main.py -v --no-report

# Список доступных проверок
python3 main.py --list-checks
```

---

## Структура проекта

```
linux-security-auditor/
├── main.py                 # Точка входа, CLI
├── config.yaml             # Конфигурация
├── requirements.txt
├── auditor/
│   ├── __init__.py
│   ├── core.py             # Оркестратор
│   ├── report.py           # Генерация Markdown + HTML
│   ├── utils.py            # Общие утилиты и модели
│   └── checks/
│       ├── users.py
│       ├── ssh.py
│       ├── permissions.py
│       ├── network.py
│       ├── packages.py
│       ├── services.py
│       ├── firewall.py
│       └── cron.py
├── reports/                # Сгенерированные отчёты
└── README.md
```

---

## Пример вывода

```
╔══════════════════════════════════════════════════╗
║         Linux Security Auditor  v1.0             ║
║     Portfolio project for InfoSec specialists    ║
╚══════════════════════════════════════════════════╝

           Результаты аудита
┌──────────┬────────────┐
│ Уровень  │ Количество │
├──────────┼────────────┤
│ HIGH     │ 2          │
│ MEDIUM   │ 3          │
│ LOW      │ 1          │
│ INFO     │ 5          │
│ PASS     │ 4          │
└──────────┴────────────┘

Всего проблем (C+H+M+L): 6
```

Отчёты сохраняются в `reports/audit_YYYYMMDD_HHMMSS.md` и `.html`.

---

## Конфигурация (`config.yaml`)

```yaml
min_severity: info          # минимальный уровень для отображения

checks:
  users: true
  ssh: true
  permissions: true
  network: true
  packages: true
  services: true
  firewall: true
  cron: true

report:
  output_dir: reports
  formats:
    - markdown
    - html
  include_passed: false
```

---

## Технологии

- **Python 3.10+**
- **rich** — красивый CLI
- **PyYAML** — конфигурация
- Стандартная библиотека (`subprocess`, `pwd`, `grp`, `os`)

---

## Что показывает этот проект в портфолио

- Умение писать модульный, расширяемый код
- Понимание типичных misconfigurations Linux
- Работа с системой (права, процессы, сеть, пакеты)
- Генерация отчётов (Markdown + HTML)
- CLI-дизайн и обработка ошибок
- Практический подход к hardening / audit

---

## Возможные улучшения (для дальнейшего развития)

- [ ] Интеграция с CVE-базами (OSV / NVD API)
- [ ] Поддержка Ansible-подобного вывода remediation
- [ ] JSON-отчёт + экспорт в SIEM
- [ ] Docker-образ
- [ ] Проверки AppArmor / SELinux
- [ ] Сравнение с CIS Benchmarks

---

## Лицензия

MIT

---

*Проект создан как демонстрация навыков для резюме специалиста по информационной безопасности.*
