package main

import (
	"bufio"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"net"
	"os"
	"sort"
	"strconv"
	"strings"
	"text/tabwriter"
	"time"

	"sqlz/internal/color"
	"sqlz/internal/discovery"
	"sqlz/internal/models"
	"sqlz/internal/modules/connectiontest"
	"sqlz/internal/modules/databases"
	"sqlz/internal/modules/links"
	"sqlz/internal/modules/logins"
	"sqlz/internal/modules/privs"
	"sqlz/internal/modules/shell"
	"sqlz/internal/modules/sqlquery"
	"sqlz/internal/modules/tables"
	"sqlz/internal/mssql"
	"sqlz/internal/runner"
	"sqlz/internal/socks5"
)

var (
	ldapServerVal string
	dcIPVal       string
	baseDNVal     string

	hostVal    string
	portVal    int
	targetsVal string
	nsVal      string

	domainVal   string
	usernameVal string
	passwordVal string
	authVal     string

	dbNameVal string

	sqlVal         string
	cmdVal         string
	enableShellVal bool
	revertShellVal bool

	jsonOutVal bool
	workersVal int

	proxyVal string
)

func init() {
	flag.StringVar(&ldapServerVal, "ldap", "", "")
	flag.StringVar(&dcIPVal, "dc-ip", "", "")
	flag.StringVar(&dcIPVal, "dc", "", "")
	flag.StringVar(&baseDNVal, "base-dn", "", "")

	flag.StringVar(&hostVal, "host", "", "")
	flag.StringVar(&hostVal, "H", "", "")
	flag.IntVar(&portVal, "port", 1433, "")
	flag.IntVar(&portVal, "P", 1433, "")
	flag.StringVar(&targetsVal, "targets", "", "")
	flag.StringVar(&targetsVal, "t", "", "")
	flag.StringVar(&nsVal, "nameserver", "", "")
	flag.StringVar(&nsVal, "ns", "", "")

	flag.StringVar(&usernameVal, "username", "", "")
	flag.StringVar(&usernameVal, "u", "", "")
	flag.StringVar(&passwordVal, "password", "", "")
	flag.StringVar(&passwordVal, "p", "", "")
	flag.StringVar(&domainVal, "domain", "", "")
	flag.StringVar(&domainVal, "d", "", "")
	flag.StringVar(&authVal, "auth", "sql", "")

	flag.StringVar(&dbNameVal, "db", "master", "")

	flag.StringVar(&sqlVal, "sql", "", "")
	flag.StringVar(&sqlVal, "q", "", "")
	flag.StringVar(&cmdVal, "command", "", "")
	flag.StringVar(&cmdVal, "c", "", "")
	flag.BoolVar(&enableShellVal, "enable-shell", false, "")
	flag.BoolVar(&revertShellVal, "revert-shell", false, "")

	flag.BoolVar(&jsonOutVal, "json", false, "")
	flag.BoolVar(&jsonOutVal, "j", false, "")
	flag.IntVar(&workersVal, "workers", 50, "")
	flag.IntVar(&workersVal, "w", 50, "")

	flag.StringVar(&proxyVal, "proxy", "", "")
	flag.StringVar(&proxyVal, "x", "", "")

	flag.Usage = printHelp
}

func main() {
	if len(os.Args) < 2 {
		printHelp()
		return
	}

	cmd := os.Args[1]
	if cmd == "-h" || cmd == "--help" || cmd == "help" {
		printHelp()
		return
	}

	flag.CommandLine.Parse(os.Args[2:])

	// no colors in JSON mode or when piped
	if jsonOutVal {
		color.Disable()
	}

	switch cmd {
	case "discover":
		runDiscover()
	case "scan":
		runScan()
	case "info":
		runInfo()
	case "databases", "dbs":
		runDatabases()
	case "tables":
		runTables()
	case "query":
		runQuery()
	case "shell":
		runShell()
	case "links":
		runLinks()
	case "logins":
		runLogins()
	case "privs":
		runPrivs()
	default:
		fmt.Fprintf(os.Stderr, "unknown command: %s\n\n", cmd)
		printHelp()
		os.Exit(1)
	}
}

// ---- connection helpers ----

func getDC() string {
	if dcIPVal != "" {
		return dcIPVal
	}
	return ldapServerVal
}

func getAuth() mssql.AuthType {
	switch strings.ToLower(authVal) {
	case "windows", "win":
		return mssql.AuthWindows
	default:
		return mssql.AuthSQL
	}
}

func getDialer() mssql.Dialer {
	if proxyVal == "" {
		return nil
	}
	d, err := socks5.Parse(proxyVal)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s invalid proxy: %v\n", color.Fail("[-]"), err)
		os.Exit(1)
	}
	return d
}

func getInstances() ([]models.SQLInstance, error) {
	var instances []models.SQLInstance
	var err error

	switch {
	case targetsVal != "":
		instances, err = instancesFromFile(targetsVal)
	case hostVal != "":
		instances = []models.SQLInstance{{Hostname: hostVal, Port: portVal}}
	default:
		dc := getDC()
		if dc == "" {
			return nil, fmt.Errorf("specify -H/--host, -t/--targets, or -dc/--dc-ip")
		}
		instances, err = discovery.DiscoverSQLInstances(discovery.LDAPConfig{
			Server:   dc,
			BaseDN:   baseDNVal,
			Domain:   domainVal,
			Username: usernameVal,
			Password: passwordVal,
			Dialer:   getDialer(),
		})
	}
	if err != nil {
		return nil, err
	}

	// Resolve hostnames via nameserver.
	// Default NS: DC IP (when -dc is set). Override with -ns.
	ns := nsVal
	if ns == "" {
		ns = getDC()
	}
	if ns != "" {
		resolveInstances(instances, ns)
	}

	return instances, nil
}

// resolveInstances sets ConnHost on each instance by resolving via ns.
// If the hostname is already an IP, or ConnHost is already set, skip it.
func resolveInstances(instances []models.SQLInstance, ns string) {
	r := &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, "udp", net.JoinHostPort(ns, "53"))
		},
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	for i := range instances {
		if instances[i].ConnHost != "" {
			continue
		}
		// skip if already an IP
		if net.ParseIP(instances[i].Hostname) != nil {
			continue
		}
		addrs, err := r.LookupHost(ctx, instances[i].Hostname)
		if err != nil {
			continue
		}
		for _, addr := range addrs {
			if ip := net.ParseIP(addr); ip != nil && ip.To4() != nil {
				instances[i].ConnHost = addr
				break
			}
		}
	}
}

func instancesFromFile(path string) ([]models.SQLInstance, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open targets file: %w", err)
	}
	defer f.Close()

	var instances []models.SQLInstance
	scanner := bufio.NewScanner(f)
	lineNum := 0
	for scanner.Scan() {
		lineNum++
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		inst, err := parseTarget(line)
		if err != nil {
			return nil, fmt.Errorf("line %d: invalid target %q: %w", lineNum, line, err)
		}
		instances = append(instances, inst)
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	if len(instances) == 0 {
		return nil, fmt.Errorf("no targets found in %s", path)
	}
	return instances, nil
}

func parseTarget(s string) (models.SQLInstance, error) {
	if strings.Contains(s, ":") {
		host, portStr, err := net.SplitHostPort(s)
		if err != nil {
			return models.SQLInstance{}, err
		}
		p, err := strconv.Atoi(portStr)
		if err != nil {
			return models.SQLInstance{}, fmt.Errorf("invalid port: %s", portStr)
		}
		return models.SQLInstance{Hostname: host, Port: p}, nil
	}
	return models.SQLInstance{Hostname: s, Port: 1433}, nil
}

func runnerCfg() runner.Config {
	return runner.Config{
		Workers:  workersVal,
		Username: usernameVal,
		Password: passwordVal,
		Domain:   domainVal,
		AuthType: getAuth(),
		Database: dbNameVal,
		Dialer:   getDialer(),
	}
}

func getClient() (*mssql.Client, models.SQLInstance, error) {
	instances, err := getInstances()
	if err != nil {
		return nil, models.SQLInstance{}, err
	}
	if len(instances) == 0 {
		return nil, models.SQLInstance{}, fmt.Errorf("no instances found")
	}
	inst := instances[0]
	client, err := mssql.New(mssql.Config{
		Server:   inst.ConnectionHost(),
		Port:     inst.Port,
		Username: usernameVal,
		Password: passwordVal,
		Domain:   domainVal,
		Database: dbNameVal,
		AuthType: getAuth(),
		Dialer:   getDialer(),
	})
	if err != nil {
		return nil, inst, fmt.Errorf("connect %s: %w", inst.Address(), err)
	}
	return client, inst, nil
}

// ---- output helpers ----

func printJSON(v any) {
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	_ = enc.Encode(v)
}

func tw() *tabwriter.Writer {
	return tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
}

func positionalOrFlag(flagVal string) string {
	if flagVal != "" {
		return flagVal
	}
	if args := flag.Args(); len(args) > 0 {
		return strings.Join(args, " ")
	}
	return ""
}

// hostStr formats host:port with color
func hostStr(hostname string, port int) string {
	return color.Host(fmt.Sprintf("%s:%d", hostname, port))
}

// boolPriv colors a boolean role membership
func boolPriv(b bool) string {
	if b {
		return color.Danger("true")
	}
	return color.Dim("false")
}

// boolState colors a generic on/off value (green=good, dim=off)
func boolState(b bool) string {
	if b {
		return color.Good("true")
	}
	return color.Dim("false")
}

// ---- discover ----

func runDiscover() {
	instances, err := getInstances()
	if err != nil {
		die(err)
	}

	if jsonOutVal {
		printJSON(instances)
		return
	}

	fmt.Printf("%s Found %s SQL Server instance(s)\n\n",
		color.Info("[*]"),
		color.Count(fmt.Sprintf("%d", len(instances))))

	w := tw()
	fmt.Fprintln(w, color.Bold("HOST\tPORT\tSPN"))
	fmt.Fprintln(w, color.Dim("----\t----\t---"))
	for _, i := range instances {
		fmt.Fprintf(w, "%s\t%d\t%s\n", i.Hostname, i.Port, color.Dim(i.SPN))
	}
	w.Flush()
}

// ---- scan ----

func runScan() {
	instances, err := getInstances()
	if err != nil {
		die(err)
	}

	fmt.Printf("%s Scanning %s instance(s) with %s workers...\n\n",
		color.Info("[*]"),
		color.Count(fmt.Sprintf("%d", len(instances))),
		color.Count(fmt.Sprintf("%d", workersVal)))

	type scanRow struct {
		Host    string `json:"host"`
		Port    int    `json:"port"`
		Auth    bool   `json:"authenticated"`
		Version string `json:"version,omitempty"`
		Error   string `json:"error,omitempty"`
	}
	var all []scanRow
	ok := 0

	connectiontest.Run(instances, connectiontest.Options{
		Workers:  workersVal,
		Username: usernameVal,
		Password: passwordVal,
		Domain:   domainVal,
		AuthType: getAuth(),
		Dialer:   getDialer(),
	}, func(r connectiontest.Result) {
		errStr := ""
		if r.Error != nil {
			errStr = r.Error.Error()
		}
		all = append(all, scanRow{r.Instance.Hostname, r.Instance.Port, r.Authenticated, r.Version, errStr})
		if r.Authenticated {
			ok++
		}
		if !jsonOutVal {
			if r.Authenticated {
				fmt.Printf("%s %s   %s   %s\n",
					color.OK("[OK]"),
					hostStr(r.Instance.Hostname, r.Instance.Port),
					color.Bold(r.Login),
					formatRoles(r.Roles))
			} else {
				fmt.Printf("%s %s\n", color.Fail("[FAIL]"), hostStr(r.Instance.Hostname, r.Instance.Port))
			}
		}
	})

	if jsonOutVal {
		printJSON(all)
		return
	}
	fmt.Printf("\n%s %s/%d accessible\n",
		color.OK("[+]"),
		color.Count(fmt.Sprintf("%d", ok)),
		len(instances))
}

// ---- info ----

type serverInfo struct {
	ServerName     string `json:"server_name,omitempty"`
	Edition        string `json:"edition,omitempty"`
	ProductVersion string `json:"product_version,omitempty"`
	ProductLevel   string `json:"product_level,omitempty"`
	IsClustered    bool   `json:"is_clustered"`
	IsSysadmin     bool   `json:"is_sysadmin"`
	ServiceAccount string `json:"service_account,omitempty"`
}

func runInfo() {
	instances, err := getInstances()
	if err != nil {
		die(err)
	}

	results := runner.Run(instances, runnerCfg(), func(client *mssql.Client) (serverInfo, error) {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()

		info := serverInfo{}
		_ = client.QueryRow(`SELECT @@SERVERNAME`).Scan(&info.ServerName)

		rows, err := client.Query(ctx, `
			SELECT
				CAST(SERVERPROPERTY('Edition') AS nvarchar(128))       AS edition,
				CAST(SERVERPROPERTY('ProductVersion') AS nvarchar(32)) AS product_version,
				CAST(SERVERPROPERTY('ProductLevel') AS nvarchar(32))   AS product_level,
				CAST(SERVERPROPERTY('IsClustered') AS int)             AS is_clustered,
				IS_SRVROLEMEMBER('sysadmin')                           AS is_sysadmin
		`)
		if err != nil {
			return info, err
		}
		if len(rows) > 0 {
			row := rows[0]
			info.Edition, _ = row["edition"].(string)
			info.ProductVersion, _ = row["product_version"].(string)
			info.ProductLevel, _ = row["product_level"].(string)
			info.IsClustered = intVal(row, "is_clustered") == 1
			info.IsSysadmin = intVal(row, "is_sysadmin") == 1
		}
		_ = client.QueryRow(`SELECT TOP 1 service_account FROM sys.dm_server_services`).
			Scan(&info.ServiceAccount)

		return info, nil
	})

	if jsonOutVal {
		printJSON(results)
		return
	}

	for _, r := range results {
		if r.Error != "" {
			fmt.Printf("%s %s — %s\n", color.Fail("[-]"), hostStr(r.Instance.Hostname, r.Instance.Port), r.Error)
			continue
		}
		i := r.Value
		fmt.Printf("\n%s %s\n", color.OK("[+]"), hostStr(r.Instance.Hostname, r.Instance.Port))
		fmt.Printf("    Server Name   : %s\n", color.Bold(i.ServerName))
		fmt.Printf("    Edition       : %s\n", i.Edition)
		fmt.Printf("    Version       : %s\n", color.Count(i.ProductVersion))
		fmt.Printf("    Level         : %s\n", i.ProductLevel)
		fmt.Printf("    Clustered     : %s\n", boolState(i.IsClustered))
		fmt.Printf("    Sysadmin      : %s\n", boolPriv(i.IsSysadmin))
		fmt.Printf("    Svc Account   : %s\n", color.Dim(i.ServiceAccount))
	}
}

// ---- databases ----

func runDatabases() {
	instances, err := getInstances()
	if err != nil {
		die(err)
	}

	results := runner.Run(instances, runnerCfg(), func(client *mssql.Client) ([]databases.Database, error) {
		return databases.Get(client)
	})

	if jsonOutVal {
		printJSON(results)
		return
	}

	for _, r := range results {
		if r.Error != "" {
			fmt.Printf("%s %s — %s\n", color.Fail("[-]"), hostStr(r.Instance.Hostname, r.Instance.Port), r.Error)
			continue
		}
		fmt.Printf("\n%s %s — %s database(s)\n",
			color.OK("[+]"),
			hostStr(r.Instance.Hostname, r.Instance.Port),
			color.Count(fmt.Sprintf("%d", len(r.Value))))

		w := tw()
		fmt.Fprintln(w, color.Bold("    NAME\tID\tSTATE\tOWNER\tREAD_ONLY"))
		for _, db := range r.Value {
			state := db.State
			if db.State == "ONLINE" {
				state = color.Good(db.State)
			} else if db.State != "" {
				state = color.Warn(db.State)
			}
			readOnly := color.Dim("false")
			if db.IsReadOnly {
				readOnly = color.Warn("true")
			}
			fmt.Fprintf(w, "    %s\t%d\t%s\t%s\t%s\n",
				db.Name, db.ID, state, db.Owner, readOnly)
		}
		w.Flush()
	}
}

// ---- tables ----

func runTables() {
	instances, err := getInstances()
	if err != nil {
		die(err)
	}

	results := runner.Run(instances, runnerCfg(), func(client *mssql.Client) ([]tables.Table, error) {
		return tables.Get(client)
	})

	if jsonOutVal {
		printJSON(results)
		return
	}

	for _, r := range results {
		if r.Error != "" {
			fmt.Printf("%s %s — %s\n", color.Fail("[-]"), hostStr(r.Instance.Hostname, r.Instance.Port), r.Error)
			continue
		}
		fmt.Printf("\n%s %s %s — %s table(s)\n",
			color.OK("[+]"),
			hostStr(r.Instance.Hostname, r.Instance.Port),
			color.Dim(fmt.Sprintf("[db=%s]", dbNameVal)),
			color.Count(fmt.Sprintf("%d", len(r.Value))))

		w := tw()
		fmt.Fprintln(w, color.Bold("    SCHEMA\tNAME\tTYPE"))
		for _, t := range r.Value {
			fmt.Fprintf(w, "    %s\t%s\t%s\n", t.Schema, t.Name, color.Dim(t.Type))
		}
		w.Flush()
	}
}

// ---- query ----

func runQuery() {
	q := positionalOrFlag(sqlVal)
	if q == "" {
		fmt.Fprintln(os.Stderr, color.Fail("[-]")+` specify a query:  sqlz query -H host -u user -p pass "SELECT @@VERSION"`)
		os.Exit(1)
	}

	client, inst, err := getClient()
	if err != nil {
		die(err)
	}
	defer client.Close()

	rows, err := sqlquery.Run(client, q)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s query failed on %s: %v\n", color.Fail("[-]"), hostStr(inst.Hostname, inst.Port), err)
		os.Exit(1)
	}

	if jsonOutVal {
		printJSON(rows)
		return
	}

	if len(rows) == 0 {
		fmt.Printf("%s No rows returned\n", color.Info("[*]"))
		return
	}

	cols := sortedKeys(rows[0])
	w := tw()
	fmt.Fprintln(w, color.Bold(strings.Join(cols, "\t")))
	for _, row := range rows {
		vals := make([]string, len(cols))
		for i, col := range cols {
			vals[i] = fmt.Sprintf("%v", row[col])
		}
		fmt.Fprintln(w, strings.Join(vals, "\t"))
	}
	w.Flush()
}

// ---- shell ----

func runShell() {
	cmd := positionalOrFlag(cmdVal)
	if cmd == "" {
		fmt.Fprintln(os.Stderr, color.Fail("[-]")+` specify a command:  sqlz shell -H host -u user -p pass "whoami"`)
		os.Exit(1)
	}

	client, inst, err := getClient()
	if err != nil {
		die(err)
	}
	defer client.Close()

	enabled, err := shell.IsEnabled(client)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s cannot check xp_cmdshell on %s: %v\n",
			color.Fail("[-]"), hostStr(inst.Hostname, inst.Port), err)
		os.Exit(1)
	}

	if !enabled {
		if !enableShellVal {
			fmt.Fprintf(os.Stderr, "%s xp_cmdshell is disabled on %s. Add --enable-shell to enable it (requires sysadmin).\n",
				color.Fail("[-]"), hostStr(inst.Hostname, inst.Port))
			os.Exit(1)
		}
		fmt.Printf("%s Enabling xp_cmdshell on %s...\n", color.Info("[*]"), hostStr(inst.Hostname, inst.Port))
		if err := shell.Enable(client); err != nil {
			fmt.Fprintf(os.Stderr, "%s %v\n", color.Fail("[-]"), err)
			os.Exit(1)
		}
		fmt.Printf("%s xp_cmdshell enabled\n", color.OK("[+]"))
	}

	fmt.Printf("%s %s\n\n", color.Info(fmt.Sprintf("[*] %s$", inst.Address())), color.Bold(cmd))

	lines, err := shell.Run(client, cmd)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s command failed: %v\n", color.Fail("[-]"), err)
		os.Exit(1)
	}

	if jsonOutVal {
		printJSON(lines)
	} else {
		for _, line := range lines {
			fmt.Println(line)
		}
	}

	if revertShellVal {
		fmt.Printf("\n%s Disabling xp_cmdshell on %s...\n", color.Info("[*]"), hostStr(inst.Hostname, inst.Port))
		_ = shell.Disable(client)
	}
}

// ---- links ----

func runLinks() {
	instances, err := getInstances()
	if err != nil {
		die(err)
	}

	results := runner.Run(instances, runnerCfg(), func(client *mssql.Client) ([]links.LinkedServer, error) {
		return links.Get(client)
	})

	if jsonOutVal {
		printJSON(results)
		return
	}

	for _, r := range results {
		if r.Error != "" {
			fmt.Printf("%s %s — %s\n", color.Fail("[-]"), hostStr(r.Instance.Hostname, r.Instance.Port), r.Error)
			continue
		}
		if len(r.Value) == 0 {
			fmt.Printf("%s %s — no linked servers\n", color.Info("[*]"), hostStr(r.Instance.Hostname, r.Instance.Port))
			continue
		}
		fmt.Printf("\n%s %s — %s linked server(s)\n",
			color.OK("[+]"),
			hostStr(r.Instance.Hostname, r.Instance.Port),
			color.Count(fmt.Sprintf("%d", len(r.Value))))

		w := tw()
		fmt.Fprintln(w, color.Bold("    NAME\tPROVIDER\tDATA SOURCE\tRPC OUT\tREMOTE LOGIN"))
		for _, ls := range r.Value {
			fmt.Fprintf(w, "    %s\t%s\t%s\t%s\t%s\n",
				color.Bold(ls.Name), ls.Provider, ls.DataSource,
				boolState(ls.IsRPCOut), boolState(ls.IsRemote))
		}
		w.Flush()
	}
}

// ---- logins ----

func runLogins() {
	instances, err := getInstances()
	if err != nil {
		die(err)
	}

	results := runner.Run(instances, runnerCfg(), func(client *mssql.Client) ([]logins.Login, error) {
		return logins.Get(client)
	})

	if jsonOutVal {
		printJSON(results)
		return
	}

	for _, r := range results {
		if r.Error != "" {
			fmt.Printf("%s %s — %s\n", color.Fail("[-]"), hostStr(r.Instance.Hostname, r.Instance.Port), r.Error)
			continue
		}
		fmt.Printf("\n%s %s — %s login(s)\n",
			color.OK("[+]"),
			hostStr(r.Instance.Hostname, r.Instance.Port),
			color.Count(fmt.Sprintf("%d", len(r.Value))))

		w := tw()
		fmt.Fprintln(w, color.Bold("    NAME\tTYPE\tDISABLED\tCREATED"))
		for _, l := range r.Value {
			name := l.Name
			disabled := color.Good("false") // active login — green
			if l.Disabled {
				name = color.Dim(l.Name)     // disabled — grey out the name too
				disabled = color.Dim("true")
			}
			fmt.Fprintf(w, "    %s\t%s\t%s\t%s\n",
				name, color.Dim(l.Type), disabled, color.Dim(l.Created))
		}
		w.Flush()
	}
}

// ---- privs ----

func runPrivs() {
	instances, err := getInstances()
	if err != nil {
		die(err)
	}

	results := runner.Run(instances, runnerCfg(), func(client *mssql.Client) (*privs.ServerPrivs, error) {
		return privs.Get(client)
	})

	if jsonOutVal {
		printJSON(results)
		return
	}

	for _, r := range results {
		if r.Error != "" {
			fmt.Printf("%s %s — %s\n", color.Fail("[-]"), hostStr(r.Instance.Hostname, r.Instance.Port), r.Error)
			continue
		}
		p := r.Value
		fmt.Printf("\n%s %s\n", color.OK("[+]"), hostStr(r.Instance.Hostname, r.Instance.Port))
		fmt.Printf("    Login           : %s\n", color.Bold(p.Login))
		fmt.Printf("    DB User         : %s\n", color.Bold(p.DBUser))
		fmt.Printf("    sysadmin        : %s\n", boolPriv(p.IsSysadmin))
		fmt.Printf("    securityadmin   : %s\n", boolPriv(p.IsSecurityAdmin))
		fmt.Printf("    serveradmin     : %s\n", boolPriv(p.IsServerAdmin))
		fmt.Printf("    setupadmin      : %s\n", boolPriv(p.IsSetupAdmin))
		fmt.Printf("    processadmin    : %s\n", boolPriv(p.IsProcessAdmin))
		fmt.Printf("    diskadmin       : %s\n", boolPriv(p.IsDiskAdmin))
		fmt.Printf("    dbcreator       : %s\n", boolPriv(p.IsDBCreator))
		fmt.Printf("    bulkadmin       : %s\n", boolPriv(p.IsBulkAdmin))
		if len(p.Permissions) > 0 {
			fmt.Printf("    Server perms    : %s\n", color.Dim(strings.Join(p.Permissions, ", ")))
		}
	}
}

// ---- help ----

func printHelp() {
	fmt.Print(`
sqlz — PowerUpSQL rewritten in Go

Usage: sqlz <command> [flags] [args]

Commands:
  discover    Find SQL instances via LDAP SPN search
  scan        Test auth + show privileges for each instance
  info        Server version, edition, sysadmin, service account
  databases   List databases  (alias: dbs)
  tables      List tables     (use --db to select database)
  query       Run SQL query
  shell       Execute OS command via xp_cmdshell
  links       Show linked servers
  logins      List SQL/Windows logins
  privs       Current user privileges and role memberships

Target:
  -H, --host        Single SQL Server host
  -P, --port        Port (default: 1433)
  -t, --targets     File with targets, one per line (host or host:port)
  -dc,--dc-ip       Domain Controller IP for LDAP discovery
      --ldap        LDAP server (same as -dc)
      --base-dn     LDAP base DN (auto-detected from --domain)
  -ns,--nameserver  DNS server for hostname resolution
                    (default: DC IP when -dc is set)

Auth:
  -u, --username    Username
  -p, --password    Password
  -d, --domain      Domain
      --auth        Auth type: sql (default) | windows

Options:
      --db            Database (default: master)
  -q, --sql           SQL query  (query command)
  -c, --command       OS command (shell command)
      --enable-shell  Enable xp_cmdshell (requires sysadmin)
      --revert-shell  Disable xp_cmdshell after running
  -j, --json          JSON output
  -w, --workers       Concurrency (default: 50)
  -x, --proxy         SOCKS5 proxy (e.g. socks5://127.0.0.1:1080)

Examples:
  # Discovery via domain
  sqlz discover -dc 10.0.0.1 -d corp.local -u user -p pass

  # Scan a single host
  sqlz scan -H 10.0.0.5 -u sa -p Password1

  # Scan from file (host:port per line)
  sqlz scan -t targets.txt -u sa -p Password1

  # Enumerate databases on all targets in file
  sqlz databases -t targets.txt -u sa -p Password1

  # Shell via xp_cmdshell
  sqlz shell -H 10.0.0.5 -u sa -p Password1 --enable-shell "whoami /all"

  # Query with JSON output
  sqlz query -H 10.0.0.5 -u sa -p Password1 "SELECT @@VERSION" -j

  # Route all traffic through SOCKS5 proxy
  sqlz scan -H 10.0.0.5 -u sa -p Password1 --proxy socks5://127.0.0.1:1080
  sqlz discover -dc 10.0.0.1 -d corp.local -u user -p pass -x socks5://127.0.0.1:1080

`)}


// ---- utils ----

// formatRoles renders a role list: sysadmin in bold red, others in yellow.
func formatRoles(roles []string) string {
	if len(roles) == 0 {
		return color.Dim("(no roles)")
	}
	parts := make([]string, 0, len(roles))
	for _, r := range roles {
		if r == "sysadmin" {
			parts = append(parts, color.Danger("["+r+"]"))
		} else {
			parts = append(parts, color.Warn(r))
		}
	}
	return strings.Join(parts, " ")
}

func die(err error) {
	fmt.Fprintf(os.Stderr, "%s %v\n", color.Fail("[-]"), err)
	os.Exit(1)
}

func intVal(row map[string]any, key string) int {
	switch v := row[key].(type) {
	case int64:
		return int(v)
	case int32:
		return int(v)
	case int:
		return v
	}
	return 0
}

func sortedKeys(m map[string]any) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}
