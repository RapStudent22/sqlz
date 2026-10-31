# sqlz

[![Go Version](https://img.shields.io/badge/go-1.21%2B-blue)](https://go.dev/)
[![Platform](https://img.shields.io/badge/platform-linux%20%7C%20windows%20%7C%20macos-lightgrey)]()
[![License](https://img.shields.io/badge/license-MIT-green)]()

**sqlz** — инструмент для аудита Microsoft SQL Server, написанный на Go. Переосмысление PowerUpSQL в виде единого самодостаточного бинарника: обнаружение инстансов в домене, проверка учётных данных, сбор метаданных и выполнение запросов — с параллельным выполнением и без установки чего-либо на целевую систему.

---

## Содержание

- [Возможности](#возможности)
- [Установка](#установка)
- [Быстрый старт](#быстрый-старт)
- [Команды](#команды)
- [Аутентификация](#аутентификация)
- [Kerberos](#kerberos)
- [Spray-атака](#spray-атака)
- [Определение целей](#определение-целей)
- [Примеры](#примеры)
- [Ограничения](#ограничения)
- [Безопасность](#безопасность)

---

## Возможности

- **Один бинарник, ноль зависимостей.** Не требует Python, .NET, FreeTDS или клиента MSSQL. Работает на Linux, Windows и macOS.
- **Все основные схемы аутентификации:** SQL, Windows (NTLM), Kerberos, SSPI.
- **Kerberos-стек собственной реализации** (в духе impacket): без `/etc/krb5.conf`, без keytab-файлов, без переменных окружения.
- **Pass-the-hash, pass-the-key, ccache** — из коробки.
- **LDAP-discovery** по SPN `MSSQLSvc/*` для автоматического сбора целей.
- **Проверка Force Encryption** на этапе TDS pre-login — серверы, пригодные для relay, видны сразу при сканировании.
- **Параллельное выполнение** с настраиваемым числом воркеров.
- **JSON-вывод** для интеграции в пайплайны.
- **SOCKS5-проксирование всего трафика** — TDS, LDAP, KDC (порт 88) и DNS.

---

## Установка

### Через `go install`

```bash
go install github.com/RapStudent22/sqlz/cmd/sqlz@latest
```

Требуется Go 1.21 или новее.

### Готовые бинарники

Скачайте сборку под вашу платформу со страницы [Releases](https://github.com/RapStudent22/sqlz/releases).

### Сборка из исходников

Собрать всё сразу (результаты в `dist/`):

```bash
./build.sh
```

Либо кросскомпиляция под одну платформу одной командой:

```bash
# Windows (amd64)
GOOS=windows GOARCH=amd64 go build -trimpath -ldflags="-s -w" -o sqlz_windows_amd64.exe ./cmd/sqlz

# Linux (amd64)
GOOS=linux GOARCH=amd64 go build -trimpath -ldflags="-s -w" -o sqlz_linux_amd64 ./cmd/sqlz

# macOS (arm64)
GOOS=darwin GOARCH=arm64 go build -trimpath -ldflags="-s -w" -o sqlz_darwin_arm64 ./cmd/sqlz
```

---

## Быстрый старт

```bash
# Найти SQL-инстансы в домене
sqlz discover -dc 10.0.0.1 -d corp.local -u user -p pass

# Проверить учётные данные на одном хосте
sqlz scan -H 10.0.0.5 -u sa -p 'Password1'

# Просканировать список хостов
sqlz scan -t targets.txt -u sa -p 'Password1'
```

Формат файла целей — простой текст, одна запись `host` или `host:port` на строку. Строки, начинающиеся с `#`, игнорируются.

```
# targets.txt
10.0.0.5
10.0.0.6:1433
sql01.corp.local
sql02.corp.local:1433
```

---

## Команды

| Команда | Описание |
|---|---|
| `discover` | Обнаружение инстансов через LDAP-поиск по SPN `MSSQLSvc/*` |
| `scan` | Проверка аутентификации, вывод ролей (включая `sysadmin`), TDS pre-login для определения Force Encryption |
| `info` | Версия, редакция, сервисный аккаунт, наличие роли `sysadmin` у текущего логина |
| `databases` | Список баз данных |
| `tables` | Список таблиц в базе, указанной через `--db` |
| `query` | Выполнение произвольного SQL-запроса |
| `shell` | Выполнение команды ОС через `xp_cmdshell` |
| `links` | Список связанных серверов |
| `logins` | Список логинов на сервере |
| `privs` | Привилегии и роли текущего пользователя |

### Общие флаги

| Флаг | Описание |
|---|---|
| `-j`, `--json` | Вывод в JSON |
| `-v`, `--verbose` | Подробная диагностика (например, предупреждения о неудачной DNS-резолюции) |
| `-w`, `--workers` | Количество параллельных воркеров |
| `-x`, `--proxy` | SOCKS5-прокси (`socks5://host:port`) |
| `-H`, `--host` | Один целевой хост |
| `-t`, `--targets` | Файл со списком целей |

### Флаги `shell`

| Флаг | Описание |
|---|---|
| `--enable-shell` | Включить `xp_cmdshell` перед выполнением (требуется `sysadmin`) |
| `--revert-shell` | Отключить `xp_cmdshell` после выполнения |

---

## Аутентификация

Способ аутентификации задаётся флагом `--auth`:

| Значение | Описание |
|---|---|
| `sql` | Стандартная аутентификация SQL Server (по умолчанию) |
| `windows` | Встроенная аутентификация Windows через NTLM. Реализовано на чистом Go — работает с Linux против доменных учётных записей |
| `kerberos` | Полноценный Kerberos: пароль, AES-ключ, NT-хэш или ccache |
| `sspi` | Нативная Windows SSPI через `secur32` (только Windows). Использует токен текущей сессии |

### Особенности `sspi`

- Для доменной сессии учётные данные не требуются вовсе.
- Работает совместно с `runas /netonly` — сетевые учётные данные из токена подхватываются корректно.
- При указании IP-адреса SSPI молча переключается на NTLM. Для Kerberos нужен FQDN — это поведение самой Windows, а не особенность sqlz.

---

## Kerberos

Режим `--auth kerberos` полностью независим от системной конфигурации:

- Не читает `/etc/krb5.conf`.
- Не использует переменные окружения `KRB5_*`.
- Не требует keytab-файлов на диске.
- Realm, KDC и типы шифрования задаются флагами.
- Ключи хранятся в keytab в памяти.

### Поиск KDC

KDC определяется в следующем порядке:

1. Явное указание через `--kdc`.
2. Через `--dc-ip`.
3. DNS SRV-запрос: сначала `_kerberos._tcp.dc._msdcs.<domain>`, затем `_kerberos._tcp.<realm>`.

SRV-запросы выполняются через `--nameserver`. Найденный KDC фиксируется по IP — домен не обязан присутствовать в `/etc/resolv.conf`.

### Формирование SPN

SPN формируется автоматически по шаблону:

```
MSSQLSvc/<hostname>:<port>
```

**Важно:** подключаться следует по имени хоста, а не по IP. Discovery-команда возвращает имена хостов именно для этого.

SPN вида `MSSQLSvc/<host>:<InstanceName>` (именованный инстанс) помечается в выводе `discover` как `host\InstanceName`; его порт через LDAP неизвестен (определяется через SQL Browser), поэтому остаётся 1433.

### Типы шифрования

Типы перебираются в порядке: **AES256 → AES128 → RC4**.

При получении ошибки `KDC_ERR_ETYPE_NOSUPP` обмен повторяется для каждого типа шифрования отдельно.

### Обработка смены пароля

Если у учётной записи менялся пароль, KDC сообщает актуальный `kvno`. sqlz автоматически пересобирает keytab с корректной версией ключа и повторяет аутентификацию. Благодаря этому pass-the-key и pass-the-hash не нарушаются после ротации паролей.

### Режимы

```bash
# Пароль
sqlz scan -H sql01.corp.local -d corp.local -u user -p 'Passw0rd!' \
  --auth kerberos -dc 10.0.0.1

# Pass-the-key
# AES256 = 64 hex-символа, AES128 = 32 hex-символа
sqlz query -H sql01.corp.local -d corp.local -u user \
  --aes-key <64-hex> --auth kerberos -dc 10.0.0.1 \
  "SELECT @@VERSION"

# Pass-the-hash (NT-хэш или пара lm:nt)
sqlz scan -H sql01.corp.local -d corp.local -u user \
  --hash <32-hex> --auth kerberos -dc 10.0.0.1

# ccache (только с явным путём)
sqlz scan -H sql01.corp.local -d corp.local \
  --auth kerberos -dc 10.0.0.1 --ccache /tmp/krb5cc
```

### Kerberos в discovery

Команда `discover` (и `scan` при отсутствии явных целей) выполняет LDAP-bind через GSS-SPNEGO — аналогично impacket. Пароль в открытом виде для этого не используется.

```bash
# discovery + scan одной командой, цели из LDAP по SPN
sqlz scan -d corp.local -u user --hash <32-hex> \
  --auth kerberos -dc DC1.corp.local -ns 10.0.0.1

# Только сбор списка
sqlz discover -dc DC1.corp.local -d corp.local -u user \
  --aes-key <64-hex> --auth kerberos -ns 10.0.0.1
```

**Нюанс:** для Kerberos-discovery контроллер домена необходимо передавать **по имени** (`-dc DC1.corp.local`) — из него формируется SPN `ldap/<host>`. Если передан IP, sqlz выполнит обратный PTR-запрос через `--nameserver`. Если PTR не разрешится — будет выведена понятная ошибка с подсказкой.

---

## Spray-атака

Команда `scan` поддерживает перебор пар `user:secret` из файла. Для каждого хоста пары проверяются последовательно до первого успеха; дубликаты исключаются.

Тип секрета определяется по формату автоматически:

| Формат | Тип |
|---|---|
| Произвольная строка | Пароль |
| `p:строка` | Пароль принудительно (см. ниже) |
| 32 hex-символа | NT-хэш |
| `32-hex:32-hex` | Пара `lm:nt` |
| 64 hex-символа | AES256-ключ |

**Нюанс:** легитимный пароль из 32 (или 64) hex-символов неотличим от NT-хэша (AES-ключа) и будет распознан как хэш — в режиме `--auth sql` такой хэш отклоняется. Для таких паролей используйте префикс `p:`:

```
test5:p:deadbeefdeadbeefdeadbeefdeadbeef
```

Пример файла с учётными данными:

```
test1:Password123!
test2:8846f7eaee8fb117ad06bdd830b7586c
test3:aad3b435b51404eeaad3b435b51404ee:8846f7eaee8fb117ad06bdd830b7586c
test4:00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff
```

Запуск:

```bash
sqlz scan -t targets.txt -d corp.local --auth kerberos -dc 10.0.0.1 --spray creds.txt
```

### Ограничения режима spray

- **Требуются явно заданные цели** (`-H` или `-t`). LDAP-discovery в режиме спрея отключён намеренно: bind в LDAP глобальными учётными данными при неверном пароле — это лишние bad-password-попытки в AD без необходимости.
- **Каждый неудачный логин инкрементирует `badPwdCount`.** N пар × M хостов легко достигают порога блокировки (по умолчанию — 10 попыток). sqlz выводит предупреждение перед запуском спрея, но политику lockout необходимо контролировать самостоятельно.

---

## Определение целей

Приоритет источников целей:

1. `-t` / `--targets` — файл со списком.
2. `-H` / `--host` — один хост.
3. LDAP-discovery — выполняется **только** если не задано ни то, ни другое.

Следствия:

- Спрей и сканирование по файлу/хосту не затрагивают LDAP.
- LDAP-bind выполняется только когда цели реально берутся из домена — один раз за запуск.
- Если в имени пользователя отсутствует `@` или `\`, выполняется до трёх попыток bind в разных форматах (учитываются как неудачные).

---

## Примеры

### Discovery

```bash
sqlz discover -dc 10.0.0.1 -d corp.local -u user -p pass
```

### Сканирование

```bash
# Список хостов с проверкой Force Encryption
sqlz scan -t targets.txt -u sa -p 'Password1'

# Один хост через Windows-аутентификацию
sqlz info -H 10.0.0.5 -u administrator -p 'Password1' \
  -d corp.local --auth windows
```

### Метаданные

```bash
# Список баз
sqlz databases -H 10.0.0.5 -u sa -p 'Password1'

# Список таблиц в базе msdb
sqlz tables -H 10.0.0.5 -u sa -p 'Password1' --db msdb

# Логины и привилегии
sqlz logins -H 10.0.0.5 -u sa -p 'Password1'
sqlz privs  -H 10.0.0.5 -u sa -p 'Password1'

# Связанные серверы
sqlz links -H 10.0.0.5 -u sa -p 'Password1'
```

### Выполнение запросов и команд

```bash
# Произвольный запрос
sqlz query -H 10.0.0.5 -u sa -p 'Password1' "SELECT @@VERSION"

# Флаги можно ставить и после позиционного аргумента (query/shell)
sqlz query -H 10.0.0.5 -u sa -p 'Password1' "SELECT @@VERSION" -j

# Команда ОС с включением и отключением xp_cmdshell
sqlz shell -H 10.0.0.5 -u sa -p 'Password1' \
  --enable-shell --revert-shell "whoami"
```

### Kerberos

```bash
# Пароль
sqlz scan -H sql01.corp.local -d corp.local -u user -p pass \
  --auth kerberos -dc 10.0.0.1

# Pass-the-hash
sqlz scan -H sql01.corp.local -d corp.local -u user \
  --hash 8846f7eaee8fb117ad06bdd830b7586c \
  --auth kerberos -dc 10.0.0.1
```

### Windows: доменная сессия без учётных данных

```powershell
.\sqlz_windows_amd64.exe scan -H sql01.corp.local -d corp.local `
  --auth sspi -ns 10.0.0.1
```

### Через SOCKS5-прокси

```bash
# SQL-аутентификация
sqlz scan -H 10.0.0.5 -u sa -p 'Password1' -x socks5://127.0.0.1:1080

# Kerberos: TDS, LDAP, KDC (порт 88) и DNS — всё через прокси
sqlz scan -H sql01.corp.local -d corp.local -u user -p pass \
  --auth kerberos -dc 10.0.0.1 -x socks5://127.0.0.1:1080
```

### JSON для пайплайнов

```bash
sqlz databases -H 10.0.0.5 -u sa -p 'Password1' --json | jq .
```

---

## Ограничения

### Проксирование и Kerberos

**SOCKS5 проксирует весь трафик**, включая Kerberos:

- **TDS и LDAP** — напрямую через прокси.
- **KDC (порт 88)** — через автоматический локальный relay: Kerberos-клиент обращается к `127.0.0.1`, а relay тунелирует трафик через прокси. Ручные пробросы (`ssh -L`, `netsh portproxy`) не требуются.
- **DNS-запросы** к `--nameserver` идут по TCP через прокси.

Если KDC недоступен через прокси, sqlz завершается быстро с понятной ошибкой (внутренние таймауты ~5 секунд) — зависаний нет.

### ccache на Windows

Поддерживается только при установленном [MIT Kerberos for Windows (KfW)](https://web.mit.edu/kerberos/dist/).

### Pass-the-hash и Protected Users

Pass-the-hash не работает против учётных записей, требующих AES (группа Protected Users в AD). Ошибка классифицируется, выводится подсказка использовать `--aes-key`.

### SSPI и IP-адреса

При подключении по IP-адресу Windows SSPI молча переключается на NTLM. Для Kerberos необходим FQDN. Это поведение операционной системы, sqlz его не изменяет.

---

## Безопасность

### Обращение с секретами

- **NT-хэши и AES-ключи эквивалентны паролям.** В логи и JSON-отчёты они не записываются никогда.
- **Фиксируйте дату извлечения** AES-ключей: они меняются при смене пароля учётной записи.
- **Храните файлы со spray-данными** с ограниченными правами доступа.

### Ответственное использование

Инструмент предназначен для:

- Легитимного пентеста с письменным разрешением.
- Внутреннего аудита собственной инфраструктуры.
- CTF и учебных лабораторий.

Использование против систем без явного разрешения нарушает законодательство большинства юрисдикций и может привести к уголовной ответственности. Автор не несёт ответственности за неправомерное использование.

---

## Лицензия

MIT. См. файл [LICENSE](LICENSE) в репозитории.
