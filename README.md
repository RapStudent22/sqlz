# sqlz

Быстрый инструмент для аудита и пентеста SQL Server, написанный на Go.
Вдохновлён [PowerUpSQL](https://github.com/NetSPI/PowerUpSQL), создан ради
скорости: параллельные воркеры, один статический бинарник, ноль внешних
зависимостей. Работает на Linux, Windows и macOS.

## Возможности

- **`discover`** — поиск SQL-инстансов в домене через LDAP (SPN `MSSQLSvc/*`)
- **`scan`** — проверка учётных данных по списку целей с ролями
  (`sysadmin`, `serveradmin` и т.д.) и проверкой Force Encryption (TDS
  pre-login) — детектит relayable-инстансы
- **`info`** — версия, редакция, сервисный аккаунт, sysadmin-статус
- **`databases` / `tables`** — перечисление баз и таблиц
- **`query`** — произвольный SQL
- **`shell`** — выполнение команд ОС через `xp_cmdshell`
  (с опцией `--enable-shell` / `--revert-shell`)
- **`links`** — связанные серверы
- **`logins` / `privs`** — логины и привилегии текущего пользователя
- **Аутентификация**: SQL, Windows (NTLM), **Kerberos** (пароль,
  pass-the-key, pass-the-hash, ccache), **SSPI** (Windows)
- **Spray-режим** — перебор пар учётных записей с остановкой на первом
  успехе
- **SOCKS5-прокси** для TDS-трафика, DNS-резолв через указанный
  nameserver, JSON-вывод для автоматизации

## Установка

```bash
go install github.com/RapStudent22/sqlz/cmd/sqlz@latest
```

Либо готовые бинарники из
[Releases](https://github.com/RapStudent22/sqlz/releases).

**Сборка под все платформы** (`build.sh` кладёт результаты в `dist/`):

```bash
./build.sh
```

**Кросс-компиляция вручную:**

```bash
# Windows amd64
GOOS=windows GOARCH=amd64 go build -trimpath -ldflags="-s -w" -o sqlz_windows_amd64.exe ./cmd/sqlz

# Linux amd64
GOOS=linux GOARCH=amd64 go build -trimpath -ldflags="-s -w" -o sqlz_linux_amd64 ./cmd/sqlz
```

## Использование

```
sqlz <команда> [флаги] [аргументы]
```

### Команды

| Команда | Описание |
|---------|----------|
| `discover` | Найти SQL-инстансы через LDAP-поиск по SPN |
| `scan` | Проверить аутентификацию и показать роли (+ Force Encryption) |
| `info` | Версия сервера, редакция, sysadmin, сервисный аккаунт |
| `databases` | Список баз данных (алиас: `dbs`) |
| `tables` | Список таблиц в базе (`--db`) |
| `query` | Выполнить SQL-запрос |
| `shell` | Команда ОС через `xp_cmdshell` |
| `links` | Связанные серверы |
| `logins` | SQL/Windows-логины |
| `privs` | Привилегии и роли текущего пользователя |

### Флаги

**Цель:**

```
-H, --host        Один хост SQL Server
-P, --port        Порт (по умолчанию: 1433)
-t, --targets     Файл с целями, по одной на строку (host или host:port)
-dc, --dc-ip      IP контроллера домена (для LDAP-discovery и как KDC по умолчанию)
     --ldap       LDAP-сервер (то же, что -dc)
     --base-dn    LDAP base DN (автоопределяется из --domain)
-ns, --nameserver DNS-сервер для резолва имён (по умолчанию: IP DC)
```

**Аутентификация:**

```
-u, --username    Имя пользователя
-p, --password    Пароль
-d, --domain      Домен
     --auth       Тип аутентификации: sql (по умолчанию) | windows | kerberos | sspi
```

**Kerberos (`--auth kerberos`):**

```
     --realm       Kerberos realm (по умолчанию: upper(--domain))
     --kdc         IP/хост KDC (по умолчанию: --dc-ip, затем DNS SRV через --nameserver)
     --aes-key     AES-ключ для pass-the-key (32 hex = AES128, 64 hex = AES256)
     --hash        NT-хэш (32 hex) или пара lm:nt для pass-the-hash
     --ccache      Файл credential cache (только явный путь)
     --krb-etype   Принудительный тип шифрования: aes256,aes128,rc4
     --kvno        Версия ключа (по умолчанию: 1)
```

**Опции:**

```
     --db            База данных (по умолчанию: master)
-q, --sql            SQL-запрос (команда query)
-c, --command        Команда ОС (команда shell)
     --enable-shell  Включить xp_cmdshell (требует sysadmin)
     --revert-shell  Выключить xp_cmdshell после выполнения
-j, --json           JSON-вывод
-w, --workers        Параллелизм (по умолчанию: 50)
-x, --proxy          SOCKS5-прокси (например socks5://127.0.0.1:1080)
     --spray         Файл учётных данных для spray-режима (только scan)
```

## Аутентификация

- **`--auth sql`** (по умолчанию) — обычный SQL-логин (`sa` и т.п.).
- **`--auth windows`** — встроенная аутентификация Windows через NTLM
  (SPNEGO), чистая Go-реализация, работает и на Linux.
- **`--auth kerberos`** — Kerberos: пароль, AES-ключ (pass-the-key),
  NT-хэш (pass-the-hash) или ccache. Полностью самодостаточный,
  impacket-стиль: **не требует никакой настройки системы** (см. ниже).
- **`--auth sspi`** — только Windows: нативная аутентификация через SSPI
  (secur32) с токеном текущей сессии. Для доменной сессии флаги кредов не
  нужны вообще. Работает и через `runas /netonly` (сетевые креды из токена).

## Kerberos

`--auth kerberos` — самодостаточный стек в духе impacket: работает на
**стоковом Kali без какой-либо настройки**.

- **`/etc/krb5.conf`, `KRB5_CONFIG` и `KRB5_KTNAME` никогда не читаются.**
  Realm, KDC и типы шифрования берутся только из явных параметров.
- **Никаких keytab-файлов на диске**: AES-ключи и NT-хэши хранятся в
  keytab в памяти.
- **Порядок поиска KDC**: `--kdc` → `--dc-ip` → DNS SRV
  (`_kerberos._tcp.dc._msdcs.<домен>`, затем `_kerberos._tcp.<realm>`).
  SRV-запросы идут через `--nameserver`, найденный KDC фиксируется как IP —
  системный резолвер не участвует вообще.
- **SPN строится автоматически**: `MSSQLSvc/<hostname>:<порт>`. Подключаться
  нужно по имени хоста/FQDN (discovery выдаёт имена). Голый IP не может
  образовать валидный SPN — такая цель отклоняется с понятной ошибкой.
- **Порядок типов шифрования**: AES256 → AES128 → RC4. При
  `KDC_ERR_ETYPE_NOSUPP` обмен повторяется с каждым типом по отдельности.
- **Авто-восстановление версии ключа (kvno)**: если KDC отвечает, что ключ
  аккаунта имеет другую версию, in-memory keytab пересобирается с
  правильным kvno и обмен повторяется — pass-the-hash/key работают даже
  после множественных смен пароля.
- **Windows без кредов** (`--auth kerberos` без `--password`/`--aes-key`/
  `--hash`/`--ccache`): автоматический fallback на SSPI (сессионный токен).
- Ошибки классифицируются и объясняются: неверный пароль/хэш/ключ
  (`PREAUTH_FAILED`), рассинхрон часов (`KRB_AP_ERR_SKEW` — синхронизируйте
  время по NTP), отсутствие SPN, отключённая учётка и т.д. В JSON-выводе
  scan появляются поля `kerberos_required` и `auth_hint`.

### Режимы

```bash
# Пароль
sqlz scan -H sql01.corp.local -d corp.local -u user -p 'Passw0rd!' --auth kerberos -dc 10.0.0.1

# Pass-the-key (AES256)
sqlz query -H sql01.corp.local -d corp.local -u user --aes-key <64-hex> --auth kerberos -dc 10.0.0.1 "SELECT @@VERSION"

# Pass-the-hash (NT-хэш или lm:nt)
sqlz scan -H sql01.corp.local -d corp.local -u user --hash <32-hex> --auth kerberos -dc 10.0.0.1

# ccache (только явный путь)
sqlz scan -H sql01.corp.local -d corp.local --auth kerberos -dc 10.0.0.1 --ccache /tmp/krb5cc
```

### Spray-режим (`scan`)

Файл с парами `user:secret` — тип секрета определяется по формату. Для
каждого хоста пары перебираются по порядку с **остановкой на первом
успехе**; дубликаты отбрасываются. Hash/aes-пары работают только с
`--auth kerberos`.

```
# user:password | user:32-hex (NT-хэш) | user:32-hex:32-hex (lm:nt) | user:64-hex (AES256)
test1:Password123!
test2:8846f7eaee8fb117ad06bdd830b7586c
test3:aad3b435b51404eeaad3b435b51404ee:8846f7eaee8fb117ad06bdd830b7586c
test4:00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff
```

```bash
sqlz scan -t targets.txt -d corp.local --auth kerberos -dc 10.0.0.1 --spray creds.txt
```

### Ограничения

- **Трафик KDC (TCP/UDP 88) не идёт через SOCKS5** — gokrb5 ходит на KDC
  напрямую. При работе с пивота используйте `--dc-ip` + локальный проброс
  порта (`ssh -L 88:dc:88` или `netsh interface portproxy`). Если KDC
  недоступен, обмен завершается быстро (встроенные 5-секундные дедлайны
  gokrb5) с понятной ошибкой — зависаний нет.
- **ccache на Windows** требует MIT Kerberos for Windows (KfW).
- **Pass-the-hash не сработает** против учёток, требующих AES (Protected
  Users): ошибка классифицируется с подсказкой использовать `--aes-key`.
- **NT-хэши и AES-ключи — это учётные данные**: sqlz никогда их не логирует
  и не пишет в JSON-отчёты. Фиксируйте дату извлечения — AES-ключи
  меняются при смене пароля.
- **SSPI**: Kerberos срабатывает только при подключении по FQDN — по IP
  будет тихий fallback на NTLM.

## Примеры

**Discovery через домен:**

```bash
sqlz discover -dc 10.0.0.1 -d corp.local -u user -p pass
```

**Скан файла целей:**

```bash
sqlz scan -t targets.txt -u sa -p Password1
```

**Информация о сервере:**

```bash
sqlz info -H 10.0.0.5 -u administrator -p Password1 -d corp.local --auth windows
```

**Базы и таблицы:**

```bash
sqlz databases -H 10.0.0.5 -u sa -p Password1
sqlz tables    -H 10.0.0.5 -u sa -p Password1 --db msdb
```

**SQL-запрос:**

```bash
sqlz query -H 10.0.0.5 -u sa -p Password1 "SELECT @@VERSION"
```

**Команда ОС через xp_cmdshell:**

```bash
sqlz shell -H 10.0.0.5 -u sa -p Password1 --enable-shell --revert-shell "whoami"
```

**Логины и привилегии:**

```bash
sqlz logins -H 10.0.0.5 -u sa -p Password1
sqlz privs  -H 10.0.0.5 -u sa -p Password1
```

**Kerberos против домена:**

```bash
# пароль
sqlz scan -H sql01.corp.local -d corp.local -u user -p pass --auth kerberos -dc 10.0.0.1

# pass-the-hash
sqlz scan -H sql01.corp.local -d corp.local -u user --hash 8846f7eaee8fb117ad06bdd830b7586c --auth kerberos -dc 10.0.0.1
```

**SSPI на Windows (доменная сессия, без кредов):**

```powershell
.\sqlz_windows_amd64.exe scan -H sql01.corp.local -d corp.local --auth sspi -ns 10.0.0.1
```

**Весь трафик через SOCKS5:**

```bash
sqlz scan -H 10.0.0.5 -u sa -p Password1 -x socks5://127.0.0.1:1080
sqlz discover -dc 10.0.0.1 -d corp.local -u user -p pass -x socks5://127.0.0.1:1080
```

**Формат файла целей:**

```
# один хост или host:port на строку, # = комментарий
10.0.0.5
10.0.0.6:1433
10.0.0.7:1435
```

**JSON-вывод:**

```bash
sqlz databases -H 10.0.0.5 -u sa -p Password1 --json | jq .
```
