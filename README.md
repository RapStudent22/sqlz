# sqlz

Переписанный на Go аналог PowerUpSQL. Инструмент для быстрого аудита SQL Server: обнаружение инстансов в домене, проверка учётных данных, извлечение метаданных и данных — одной командой, с параллельным выполнением и без установки зависимостей на целевую машину.

Работает на Linux, Windows и macOS без дополнительных зависимостей.

Ключевая особенность — поддержка аутентификации **SQL / Windows (NTLM) / Kerberos / SSPI**, включая pass-the-key, pass-the-hash и ccache. Kerberos-стек реализован полностью внутри приложения (в духе impacket): не требуется `/etc/krb5.conf`, keytab-файлов на диске или дополнительных настроек — на стандартном Kali работает из коробки.

## Установка

```bash
go install github.com/RapStudent22/sqlz/cmd/sqlz@latest
```

Либо готовые бинарники со страницы [Releases](https://github.com/RapStudent22/sqlz/releases) — для всех платформ их собирает `build.sh`:

```bash
./build.sh   # результаты в dist/
```

Для сборки под одну платформу достаточно одной команды:

```bash
GOOS=windows GOARCH=amd64 go build -trimpath -ldflags="-s -w" -o sqlz_windows_amd64.exe ./cmd/sqlz
```

## Быстрый старт

```bash
# обнаружение SQL-инстансов в домене (LDAP-поиск по SPN)
sqlz discover -dc 10.0.0.1 -d corp.local -u user -p pass

# проверка учётных данных на одном хосте
sqlz scan -H 10.0.0.5 -u sa -p Password1

# либо сразу по списку хостов
sqlz scan -t targets.txt -u sa -p Password1
```

Файл целей — обычный текст: одна запись `host` или `host:port` на строку, `#` — комментарий.

## Команды

| Команда | Назначение |
|---|---|
| `discover` | Поиск инстансов по SPN `MSSQLSvc/*` через LDAP |
| `scan` | Проверка аутентификации, вывод ролей (включая `sysadmin`), а также TDS pre-login для определения Force Encryption — серверы, пригодные для relay, видны сразу |
| `info` | Версия, редакция, сервисный аккаунт, наличие `sysadmin` у текущего логина |
| `databases` / `tables` | Список баз и таблиц (`tables` работает в базе, указанной через `--db`) |
| `query` | Выполнение произвольного SQL-запроса |
| `shell` | Выполнение команды ОС через `xp_cmdshell`; с `--enable-shell` включает процедуру (требуется `sysadmin`), с `--revert-shell` — отключает после выполнения |
| `links` | Список связанных серверов |
| `logins` / `privs` | Список логинов / привилегии и роли текущего пользователя |

Общие для всех команд параметры: `-j/--json` — вывод в JSON (удобно для обработки в скриптах), `-w/--workers` — уровень параллелизма, `-x/--proxy` — SOCKS5-прокси.

## Аутентификация

Тип задаётся флагом `--auth`:

- **`sql`** (по умолчанию) — стандартная аутентификация SQL Server (`sa` и прочие SQL-логины).
- **`windows`** — встроенная аутентификация через NTLM. Реализация на чистом Go, поэтому работает и с Linux против доменных учётных записей.
- **`kerberos`** — полноценный Kerberos: пароль, AES-ключ, NT-хэш или ccache. Подробности ниже.
- **`sspi`** — только Windows: нативная SSPI через `secur32`, использует токен текущей сессии. Для доменной сессии учётные данные не требуются. Работает и с `runas /netonly` — сетевые учётные данные из токена подхватываются корректно.

## Kerberos

Принципиальное отличие: режим `--auth kerberos` не зависит от системной конфигурации. Не читает `/etc/krb5.conf`, не использует переменные `KRB5_*`, не требует keytab-файлов — realm, KDC и типы шифрования задаются флагами, ключи хранятся в keytab в памяти.

Порядок поиска KDC: `--kdc` → `--dc-ip` → DNS SRV (`_kerberos._tcp.dc._msdcs.<домен>`, затем `_kerberos._tcp.<realm>`). SRV-запросы выполняются через `--nameserver`, а найденный KDC фиксируется по IP — домен не обязан быть прописан в `/etc/resolv.conf`.

SPN формируется автоматически: `MSSQLSvc/<hostname>:<порт>`. Отсюда правило — подключаться следует по имени хоста (discovery как раз возвращает имена).

Типы шифрования перебираются в порядке AES256 → AES128 → RC4; при получении `KDC_ERR_ETYPE_NOSUPP` обмен повторяется для каждого типа отдельно. Дополнительно: если у учётной записи менялся пароль, KDC сообщает актуальный kvno — инструмент автоматически пересобирает keytab с корректной версией ключа и повторяет аутентификацию. Благодаря этому pass-the-key/hash не нарушается после смены пароля.

Режимы:

```bash
# пароль
sqlz scan -H sql01.corp.local -d corp.local -u user -p 'Passw0rd!' --auth kerberos -dc 10.0.0.1

# pass-the-key (AES256 = 64 hex, AES128 = 32 hex)
sqlz query -H sql01.corp.local -d corp.local -u user --aes-key <64-hex> --auth kerberos -dc 10.0.0.1 "SELECT @@VERSION"

# pass-the-hash (NT-хэш или пара lm:nt)
sqlz scan -H sql01.corp.local -d corp.local -u user --hash <32-hex> --auth kerberos -dc 10.0.0.1

# ccache (только с явным путём)
sqlz scan -H sql01.corp.local -d corp.local --auth kerberos -dc 10.0.0.1 --ccache /tmp/krb5cc
```

На Windows `--auth kerberos` без явных учётных данных автоматически переключается на SSPI при работе в доменной сессии.

**Discovery также поддерживает Kerberos.** Если цели не заданы через `-H`/`-t`, scan сначала собирает инстансы из LDAP — при `--auth kerberos` этот bind выполняется через GSS-SPNEGO (аналогично impacket), а не с паролем:

```bash
# discovery + scan одной командой, цели из LDAP по SPN
sqlz scan -d corp.local -u user --hash <32-hex> --auth kerberos -dc DC1.corp.local -ns 10.0.0.1

# либо только сбор списка
sqlz discover -dc DC1.corp.local -d corp.local -u user --aes-key <64-hex> --auth kerberos -ns 10.0.0.1
```

Важно: для Kerberos-discovery контроллер домена следует передавать **по имени** (`-dc DC1.corp.local`) — из него формируется SPN `ldap/<host>`. При передаче IP выполняется обратный PTR-запрос через `--nameserver`; при неудаче выводится понятная ошибка с рекомендацией.

### Spray

`scan` поддерживает перебор пар `user:secret` из файла: для каждого хоста пары проверяются последовательно до первого успеха, дубликаты исключаются. Тип секрета определяется по формату автоматически: пароль, 32 hex — NT-хэш, `32-hex:32-hex` — lm:nt, 64 hex — AES256.

```
test1:Password123!
test2:8846f7eaee8fb117ad06bdd830b7586c
test3:aad3b435b51404eeaad3b435b51404ee:8846f7eaee8fb117ad06bdd830b7586c
test4:00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff
```

```bash
sqlz scan -t targets.txt -d corp.local --auth kerberos -dc 10.0.0.1 --spray creds.txt
```

Два важных замечания по безопасности и политикам:

- **Спрей требует явно заданных целей** (`-H` или `-t`). LDAP-discovery в режиме спрея отключён намеренно: bind в LDAP с глобальными учётными данными при неверном пароле — это лишние bad-password-попытки в AD без необходимости.
- **Каждый неудачный логин инкрементирует badPwdCount учётной записи.** N пар × M хостов легко достигают порога блокировки (по умолчанию — 10). Инструмент выводит предупреждение перед запуском спрея, но политику lockout необходимо контролировать самостоятельно.

## Источники целей

Приоритет: `-t/--targets` → `-H/--host` → и только если ни то, ни другое не задано — LDAP-discovery. То есть спрей и сканирование по файлу/хосту LDAP не затрагивают; LDAP-bind выполняется только когда цели действительно берутся из домена, и только один раз за запуск (без `@`/`\` в имени выполняется до трёх попыток bind в разных форматах — они также учитываются как неудачные).

## Ограничения и известные проблемы

- **KDC-трафик (порт 88) не проходит через SOCKS5.** Проксируется только TDS; gokrb5 обращается к KDC напрямую. При работе через пивот используйте `--dc-ip` плюс локальный проброс (`ssh -L 88:dc:88`, `netsh interface portproxy`).
- **ccache на Windows** — только при установленном MIT Kerberos for Windows (KfW).
- **Pass-the-hash не работает против учётных записей, требующих AES** (Protected Users). Ошибка классифицируется с рекомендацией использовать `--aes-key`.
- **NT-хэши и AES-ключи эквивалентны паролям.** В логи и JSON-отчёты они не записываются никогда. Фиксируйте дату извлечения: AES-ключи меняются при смене пароля.
- **SSPI по IP молча переключается на NTLM** — для Kerberos требуется FQDN. Это поведение самого Windows SSPI, а не особенность инструмента.

## Примеры

```bash
# discovery по домену
sqlz discover -dc 10.0.0.1 -d corp.local -u user -p pass

# сканирование списка с проверкой Force Encryption
sqlz scan -t targets.txt -u sa -p Password1

# информация о сервере и сервисном аккаунте
sqlz info -H 10.0.0.5 -u administrator -p Password1 -d corp.local --auth windows

# базы и таблицы
sqlz databases -H 10.0.0.5 -u sa -p Password1
sqlz tables    -H 10.0.0.5 -u sa -p Password1 --db msdb

# произвольный запрос
sqlz query -H 10.0.0.5 -u sa -p Password1 "SELECT @@VERSION"

# команда через xp_cmdshell (включить, выполнить, отключить)
sqlz shell -H 10.0.0.5 -u sa -p Password1 --enable-shell --revert-shell "whoami"

# логины и привилегии
sqlz logins -H 10.0.0.5 -u sa -p Password1
sqlz privs  -H 10.0.0.5 -u sa -p Password1

# Kerberos: пароль / pass-the-hash
sqlz scan -H sql01.corp.local -d corp.local -u user -p pass --auth kerberos -dc 10.0.0.1
sqlz scan -H sql01.corp.local -d corp.local -u user --hash 8846f7eaee8fb117ad06bdd830b7586c --auth kerberos -dc 10.0.0.1

# Windows, доменная сессия — без явных учётных данных
.\sqlz_windows_amd64.exe scan -H sql01.corp.local -d corp.local --auth sspi -ns 10.0.0.1

# всё через SOCKS5
sqlz scan -H 10.0.0.5 -u sa -p Password1 -x socks5://127.0.0.1:1080

# JSON для пайплайнов
sqlz databases -H 10.0.0.5 -u sa -p Password1 --json | jq .
```
