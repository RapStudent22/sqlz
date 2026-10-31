package main

import (
	"flag"
	"reflect"
	"testing"
)

func TestSplitArgs(t *testing.T) {
	tests := []struct {
		name      string
		in        []string
		wantFlags []string
		wantPos   []string
	}{
		{
			name:      "flags after positional (README example)",
			in:        []string{"-H", "10.0.0.5", "-u", "sa", "-p", "Password1", "SELECT @@VERSION", "-j"},
			wantFlags: []string{"-H", "10.0.0.5", "-u", "sa", "-p", "Password1", "-j"},
			wantPos:   []string{"SELECT @@VERSION"},
		},
		{
			name:      "negative number after positional stays positional",
			in:        []string{"SELECT", "-1"},
			wantFlags: nil,
			wantPos:   []string{"SELECT", "-1"},
		},
		{
			name:      "unknown flag before positional goes to the parser",
			in:        []string{"-bogus", "SELECT"},
			wantFlags: []string{"-bogus"},
			wantPos:   []string{"SELECT"},
		},
		{
			name:      "value-taking flag consumes the next token",
			in:        []string{"--kvno", "-5", "SELECT"},
			wantFlags: []string{"--kvno", "-5"},
			wantPos:   []string{"SELECT"},
		},
		{
			name:      "inline flag value",
			in:        []string{"--port=1434", "SELECT", "-j"},
			wantFlags: []string{"--port=1434", "-j"},
			wantPos:   []string{"SELECT"},
		},
		{
			name:      "double dash terminates flag parsing",
			in:        []string{"-H", "h", "--", "-j", "SELECT"},
			wantFlags: []string{"-H", "h"},
			wantPos:   []string{"-j", "SELECT"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			flags, pos := splitArgs(tt.in)
			if !reflect.DeepEqual(flags, tt.wantFlags) {
				t.Errorf("flags = %v, want %v", flags, tt.wantFlags)
			}
			if !reflect.DeepEqual(pos, tt.wantPos) {
				t.Errorf("pos = %v, want %v", pos, tt.wantPos)
			}
		})
	}
}

// TestQueryFlagAfterPositional pins the P1-1 fix end to end: the README
// example `sqlz query -H 10.0.0.5 -u sa -p Password1 "SELECT @@VERSION" -j`
// must parse -j as a flag, not as part of the query text.
func TestQueryFlagAfterPositional(t *testing.T) {
	oldSQL, oldPos, oldJSON := sqlVal, positionalArgs, jsonOutVal
	defer func() { sqlVal, positionalArgs, jsonOutVal = oldSQL, oldPos, oldJSON }()

	flagArgs, pos := splitArgs([]string{"-H", "10.0.0.5", "-u", "sa", "-p", "Password1", "SELECT @@VERSION", "-j"})
	flag.CommandLine.Parse(flagArgs)
	positionalArgs = pos

	if sqlVal != "" {
		t.Errorf("sqlVal = %q, want empty (the query came positionally)", sqlVal)
	}
	if got := positionalOrFlag(sqlVal); got != "SELECT @@VERSION" {
		t.Errorf("query = %q, want %q", got, "SELECT @@VERSION")
	}
	if !jsonOutVal {
		t.Error("-j after the positional query must still set jsonOutVal")
	}
}

func TestPositionalOrFlag(t *testing.T) {
	oldSQL, oldPos := sqlVal, positionalArgs
	defer func() { sqlVal, positionalArgs = oldSQL, oldPos }()

	sqlVal = ""
	positionalArgs = []string{"SELECT", "1"}
	if got := positionalOrFlag(sqlVal); got != "SELECT 1" {
		t.Errorf("positionalOrFlag = %q, want the joined positional args", got)
	}

	sqlVal = "flag wins"
	positionalArgs = []string{"SELECT 1"}
	if got := positionalOrFlag(sqlVal); got != "flag wins" {
		t.Errorf("flag value must win, got %q", got)
	}

	sqlVal = ""
	positionalArgs = nil
	if got := positionalOrFlag(sqlVal); got != "" {
		t.Errorf("empty expected, got %q", got)
	}
}
