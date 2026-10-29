# sqlz

Переписанный на Go PowerUpSQL. Задумывался как тулза для быстрого аудита
SQL Server'ов: нашёл домен, собрал инстансы, проверил креды, вытащил всё
интересное — и всё это одной командой, параллельно, без установки
чего-либо на целевую машину.

Собранный бинарник самодостаточен: ни Python, ни дотнет, ни MSSQL-клиента
не нужно. Работает на Linux, Windows и macOS из коробки.

Ключевое: поддержка аутентификации **SQL / Windows (NTLM) / Kerberos /
SSPI**, включая pass-the-key, pass-the-hash и ccache, причём Kerberos-стек
полностью свой, в духе impacket — никаких /etc/krb5.conf и keytab'ов на
диске, на стоковом Kali работает сразу.

## Установка

```bash
go install github.com/RapStudent22/sqlz/cmd/sqlz@latest
```

Или готовые бинарники со страницы
[Releases](https://github.com/RapStudent22/sqlz/releases) — под все
платформы их собирает `build.sh`:

```bash
./build.sh   # результаты в dist/
```

Если нужно что-то одно, кросскомпил делается одной строкой:

```bash
GOOS=windows GOARCH=amd64 go build -trimpath -ldflags="-s -w" -o sqlz_windows_amd64.exe ./cmd/sqlz
```

## Быстрый старт

```bash
# найти SQL-инстансы в домене (LDAP-поиск по SPN)
sqlz discover -dc 10.0.0.1 -d corp.local -u user -p pass

# проверить креды на одном хосте
sqlz scan -H 10.0.0.5 -u sa -p Password1

# или сразу по списку хостов
sqlz scan -t targets.txt -u sa -p Password1
```

Файл целей — просто текст: `host` или `host:port` на строку, `#` — коммент.

## Команды

| Команда | Что делает |
|---|---|
| `discover` | ищет инстансы по SPN `MSSQLSvc/*` через LDAP |
| `scan` | проверяет аутентификацию, показывает роли (`sysadmin` и пр.) и заодно тыкает TDS pre-login на Force Encryption — relayable-серверы сразу видно |
| `info` | версия, редакция, сервисный аккаунт, sysadmin ли текущий логин |
| `databases` / `tables` | базы и таблицы (`tables` живёт в базе из `--db`) |
| `query` | любой SQL |
| `shell` | команда ОС через `xp_cmdshell`; с `--enable-shell` включит его (нужен sysadmin), с `--revert-shell` выключит после себя |
| `links` | связанные серверы |
| `logins` / `privs` | список логинов / привилегии и роли текущего пользователя |

Общее для всех: `-j/--json` для вывода в JSON (удобно кормить в скрипты),
`-w/--workers` для параллелизма, `-x/--proxy` для SOCKS5.

## Аутентификация

Тип выбирается флагом `--auth`:

- **`sql`** (по умолчанию) — обычный SQL-логин, `sa` и компания.
- **`windows`** — встроенная аутентификация через NTLM. Реализация чистая
  Go, так что работает и с Linux против доменных учёток.
- **`kerberos`** — полный Kerberos: пароль, AES-ключ, NT-хэш или ccache.
  Подробности ниже.
- **`sspi`** — только Windows: нативная SSPI через secur32, берёт токен
  текущей сессии. Для доменной сессии креды вообще не нужны. Работает и с
  `runas /netonly` — сетевые креды из токена подхватываются как надо.

## Kerberos

Главное, ради чего всё затевалось: `--auth kerberos` не зависит от системы
вообще. Нет чтения `/etc/krb5.conf`, нет переменных `KRB5_*`, нет
keytab-файлов — realm, KDC и типы шифрования задаются флагами, ключи живут
в keytab в памяти.

KDC ищется в таком порядке: `--kdc` → `--dc-ip` → DNS SRV
(`_kerberos._tcp.dc._msdcs.<домен>`, потом `_kerberos._tcp.<realm>`).
SRV-запросы идут через `--nameserver`, а найденный KDC фиксируется как IP —
системный резолвер не участвует, домен лабы не обязан быть прописан в
`/etc/resolv.conf`.

SPN подставляется сам: `MSSQLSvc/<hostname>:<порт>`. Отсюда правило —
подключаться нужно по имени хоста (discovery как раз выдаёт имена), голый
IP для Kerberos не годится, и тулза честно об этом скажет, а не будет
молча падать в NTLM.

Типы шифрования перебираются в порядке AES256 → AES128 → RC4, при
`KDC_ERR_ETYPE_NOSUPP` обмен повторяется с каждым по отдельности. Ещё одна
приятная мелочь: если у учётки менялся пароль, KDC сообщает текущий kvno —
тулза сама пересоберёт keytab с правильной версией ключа и повторит вход.
Pass-the-key/hash поэтому не ломается после смен паролей.

Режимы:

```bash
# пароль
sqlz scan -H sql01.corp.local -d corp.local -u user -p 'Passw0rd!' --auth kerberos -dc 10.0.0.1

# pass-the-key (AES256 = 64 hex, AES128 = 32 hex)
sqlz query -H sql01.corp.local -d corp.local -u user --aes-key <64-hex> --auth kerberos -dc 10.0.0.1 "SELECT @@VERSION"

# pass-the-hash (NT-хэш или пара lm:nt)
sqlz scan -H sql01.corp.local -d corp.local -u user --hash <32-hex> --auth kerberos -dc 10.0.0.1

# ccache (только явный путь)
sqlz scan -H sql01.corp.local -d corp.local --auth kerberos -dc 10.0.0.1 --ccache /tmp/krb5cc
```

На Windows `--auth kerberos` без кредов сам падает в SSPI — можно вообще
не думать, какой режим выбрать, если сидишь в доменной сессии.

**Discovery тоже умеет Kerberos.** Если цели не заданы через `-H`/`-t`,
скан сначала соберёт инстансы из LDAP — и с `--auth kerberos` этот бинд
пойдёт через GSS-SPNEGO (как у impacket), а не через пароль:

```bash
# discovery + scan одной командой, цели из LDAP по SPN
sqlz scan -d corp.local -u user --hash <32-hex> --auth kerberos -dc DC1.corp.local -ns 10.0.0.1

# или просто собрать список
sqlz discover -dc DC1.corp.local -d corp.local -u user --aes-key <64-hex> --auth kerberos -ns 10.0.0.1
```

Нюанс: для Kerberos-discovery DC нужно передавать **по имени**
(`-dc DC1.corp.local`) — из него строится SPN `ldap/<host>`. Если дать IP,
попробуем обратный PTR-запрос через `--nameserver`; не получится — будет
понятная ошибка с подсказкой.

Ошибки тулза объясняет по-человечески: неверный пароль/хэш/ключ — так и
напишет, рассинхрон часов с доменом — посоветует NTP, отсутствие SPN на
цели — скажет прямо. В JSON-выводе scan для этого есть поля
`kerberos_required` и `auth_hint`.

### Spray

`scan` умеет перебирать пары `user:secret` из файла: для каждого хоста
пары пробуются по порядку до первого успеха, дубликаты выбрасываются.
Тип секрета определяется по формату сам: пароль, 32 hex — NT-хэш,
`32-hex:32-hex` — lm:nt, 64 hex — AES256.

```
test1:Password123!
test2:8846f7eaee8fb117ad06bdd830b7586c
test3:aad3b435b51404eeaad3b435b51404ee:8846f7eaee8fb117ad06bdd830b7586c
test4:00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff
```

```bash
sqlz scan -t targets.txt -d corp.local --auth kerberos -dc 10.0.0.1 --spray creds.txt
```

Два момента про безопасность и политики:

- **Спрей требует явных целей** (`-H` или `-t`). LDAP-discovery в спрее
  отключён специально: бинд в LDAP глобальными кредами при неверном пароле
  — это лишние bad-password-попытки в AD ни за что.
- **Каждый неудачный логин инкрементит badPwdCount учётки.** N пар × M
  хостов легко улетают в лок при стандартном пороге 10. Тулза печатает
  предупреждение перед стартом спрея, но следи за lockout-политикой сам.

## Откуда берутся цели

Порядок такой: `-t/--targets` → `-H/--host` → и только если не задано ни
то ни другое — LDAP-discovery. То есть спрей и скан по файлу/хосту LDAP не
трогают вообще; LDAP-бинды происходят только когда цели реально берутся из
домена, и то один раз за запуск (без `@`/`\` в имени пробуется до трёх
форматов бинда — это тоже считается за неудачные попытки, имей в виду).

## Ограничения и подводные камни

- **KDC-трафик (порт 88) мимо SOCKS5.** Проксируется только TDS; gokrb5
  ходит на KDC напрямую. С пивота — `--dc-ip` плюс локальный проброс
  (`ssh -L 88:dc:88`, `netsh interface portproxy`). Если KDC недоступен,
  тулза отваливается быстро и с понятной ошибкой — висеть не будет
  (внутренние дедлайны ~5 сек).
- **ccache на Windows** — только если стоит MIT Kerberos for Windows (KfW).
- **Pass-the-hash бессилен против учёток, требующих AES** (Protected
  Users). Ошибка при этом классифицируется с подсказкой взять `--aes-key`.
- **NT-хэши и AES-ключи — это пароли.** В логи и JSON-отчёты они не пишутся
  никогда. И записывай дату извлечения: AES-ключи меняются со сменой пароля.
- **SSPI по IP молча падает в NTLM** — для Kerberos нужен FQDN. Это
  поведение самого Windows SSPI, тулза его не выдумала.

## Примеры под разные случаи

```bash
# discovery по домену
sqlz discover -dc 10.0.0.1 -d corp.local -u user -p pass

# скан списка с проверкой Force Encryption
sqlz scan -t targets.txt -u sa -p Password1

# что за сервер и кто на нём крутится
sqlz info -H 10.0.0.5 -u administrator -p Password1 -d corp.local --auth windows

# базы, таблицы
sqlz databases -H 10.0.0.5 -u sa -p Password1
sqlz tables    -H 10.0.0.5 -u sa -p Password1 --db msdb

# произвольный запрос
sqlz query -H 10.0.0.5 -u sa -p Password1 "SELECT @@VERSION"

# команда через xp_cmdshell (включить, выполнить, выключить)
sqlz shell -H 10.0.0.5 -u sa -p Password1 --enable-shell --revert-shell "whoami"

# логины и привилегии
sqlz logins -H 10.0.0.5 -u sa -p Password1
sqlz privs  -H 10.0.0.5 -u sa -p Password1

# Kerberos: пароль / pass-the-hash
sqlz scan -H sql01.corp.local -d corp.local -u user -p pass --auth kerberos -dc 10.0.0.1
sqlz scan -H sql01.corp.local -d corp.local -u user --hash 8846f7eaee8fb117ad06bdd830b7586c --auth kerberos -dc 10.0.0.1

# Windows, доменная сессия — вообще без кредов
.\sqlz_windows_amd64.exe scan -H sql01.corp.local -d corp.local --auth sspi -ns 10.0.0.1

# всё через SOCKS5
sqlz scan -H 10.0.0.5 -u sa -p Password1 -x socks5://127.0.0.1:1080

# JSON для пайплайнов
sqlz databases -H 10.0.0.5 -u sa -p Password1 --json | jq .
```
