package color

import "os"

var enabled bool

func init() {
	if os.Getenv("NO_COLOR") != "" {
		return
	}
	fi, err := os.Stdout.Stat()
	if err != nil {
		return
	}
	mode := fi.Mode()
	// disable if stdout is a pipe or a regular file (redirect) — works on Linux and Windows
	if mode&os.ModeNamedPipe != 0 || mode.IsRegular() {
		return
	}
	enabled = true
}

func Disable() { enabled = false }

func wrap(code, s string) string {
	if !enabled {
		return s
	}
	return "\033[" + code + "m" + s + "\033[0m"
}

// Status prefixes
func OK(s string) string   { return wrap("1;32", s) } // bold green
func Fail(s string) string { return wrap("1;31", s) } // bold red
func Info(s string) string { return wrap("1;36", s) } // bold cyan
func Warn(s string) string { return wrap("1;33", s) } // bold yellow

// Values
func Danger(s string) string { return wrap("1;31", s) } // bold red  — high privilege / dangerous
func Good(s string) string   { return wrap("32", s) }   // green     — positive / active
func Dim(s string) string    { return wrap("2", s) }    // dim grey  — disabled / uninteresting
func Bold(s string) string   { return wrap("1", s) }    // bold
func Host(s string) string   { return wrap("1;96", s) } // bold bright cyan — IP/hostname
func Count(s string) string  { return wrap("1;33", s) } // bold yellow — numbers worth noticing
