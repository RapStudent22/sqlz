# sqlz

Fast SQL Server enumeration tool written in Go. Inspired by [PowerUpSQL](https://github.com/NetSPI/PowerUpSQL), built for speed — parallel workers, single binary, no dependencies.

## Install

```bash
go install github.com/RapStudent22/sqlz/cmd/sqlz@latest
```

Or download a prebuilt binary from [Releases](https://github.com/RapStudent22/sqlz/releases).

**Cross-compile for Windows:**
```bash
GOOS=windows GOARCH=amd64 go build -o sqlz.exe ./cmd/sqlz/
```

## Usage

```
sqlz <command> [flags]
```

### Commands

| Command | Description |
|---------|-------------|
| `discover` | Find SQL instances via LDAP SPN search |
| `scan` | Test authentication and show privileges |
| `info` | Server version, edition, sysadmin, service account |
| `databases` | List databases (alias: `dbs`) |
| `tables` | List tables in a database |
| `query` | Run arbitrary SQL |
| `shell` | Execute OS commands via `xp_cmdshell` |
| `links` | Show linked servers |
| `logins` | List SQL and Windows logins |
| `privs` | Current user privileges and role memberships |

### Flags

**Target:**
```
-H, --host        Single SQL Server host
-P, --port        Port (default: 1433)
-t, --targets     File with targets, one per line (host or host:port)
-dc, --dc-ip      Domain Controller IP for LDAP discovery
    --ldap        LDAP server (same as -dc)
    --base-dn     LDAP base DN (auto-detected from --domain)
-ns, --nameserver DNS server for hostname resolution (default: DC IP)
```

**Auth:**
```
-u, --username    Username
-p, --password    Password
-d, --domain      Domain
    --auth        Auth type: sql (default) | windows
```

**Options:**
```
    --db            Database (default: master)
-q, --sql           SQL query (query command)
-c, --command       OS command (shell command)
    --enable-shell  Enable xp_cmdshell (requires sysadmin)
    --revert-shell  Disable xp_cmdshell after running
-j, --json          JSON output
-w, --workers       Concurrency (default: 50)
-x, --proxy         SOCKS5 proxy (e.g. socks5://127.0.0.1:1080)
```

## Examples

**Discover SQL instances via domain:**
```bash
sqlz discover -dc 10.0.0.1 -d corp.local -u user -p pass
```

**Scan a file of targets:**
```bash
sqlz scan -t targets.txt -u sa -p Password1
```

**Get server info:**
```bash
sqlz info -H 10.0.0.5 -u administrator -p Password1 -d corp.local --auth windows
```

**List databases:**
```bash
sqlz databases -H 10.0.0.5 -u sa -p Password1
```

**Run a query:**
```bash
sqlz query -H 10.0.0.5 -u sa -p Password1 "SELECT @@VERSION"
```

**Execute OS command via xp_cmdshell:**
```bash
sqlz shell -H 10.0.0.5 -u sa -p Password1 --enable-shell --revert-shell "whoami"
```

**Enumerate logins and privileges:**
```bash
sqlz logins -H 10.0.0.5 -u sa -p Password1
sqlz privs  -H 10.0.0.5 -u sa -p Password1
```

**Route all traffic through SOCKS5 proxy:**
```bash
sqlz scan -H 10.0.0.5 -u sa -p Password1 -x socks5://127.0.0.1:1080
sqlz discover -dc 10.0.0.1 -d corp.local -u user -p pass -x socks5://127.0.0.1:1080
```

**Targets file format:**
```
# one host or host:port per line, # = comment
10.0.0.5
10.0.0.6:1433
10.0.0.7:1435
```

**JSON output:**
```bash
sqlz databases -H 10.0.0.5 -u sa -p Password1 --json | jq .
```
