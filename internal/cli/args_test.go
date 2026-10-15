package cli

import (
	"reflect"
	"testing"
)

func TestParseArgs(t *testing.T) {
	tests := []struct {
		name     string
		args     []string
		want     invocation
		wantHelp bool
		wantErr  string
	}{
		{
			name:     "help alone",
			args:     []string{"--help"},
			wantHelp: true,
		},
		{
			name:    "no arguments",
			wantErr: "missing command (check, eval or diff)",
		},
		{
			name:    "unknown command",
			args:    []string{"remove"},
			wantErr: "unknown command \"remove\"",
		},
		{
			name:    "unknown command precedes option validation",
			args:    []string{"remove", "--bad"},
			wantErr: "unknown command \"remove\"",
		},
		{
			name:    "help is not special after the command",
			args:    []string{"--help", "check"},
			wantErr: "unknown command \"--help\"",
		},
		{
			name:    "help option is not special after a command",
			args:    []string{"check", "--help"},
			wantErr: "unknown option \"--help\"",
		},
		{
			name:    "check requires one file",
			args:    []string{"check"},
			wantErr: "missing argument",
		},
		{
			name:    "eval requires two files",
			args:    []string{"eval", "rules.txt"},
			wantErr: "missing argument",
		},
		{
			name:    "diff requires two files",
			args:    []string{"diff", "old.txt"},
			wantErr: "missing argument",
		},
		{
			name:    "check rejects extra files",
			args:    []string{"check", "rules.txt", "extra.txt"},
			wantErr: "too many arguments",
		},
		{
			name:    "eval rejects extra files",
			args:    []string{"eval", "rules.txt", "flows.txt", "extra.txt"},
			wantErr: "too many arguments",
		},
		{
			name:    "diff rejects extra files",
			args:    []string{"diff", "old.txt", "new.txt", "extra.txt"},
			wantErr: "too many arguments",
		},
		{
			name:    "option is checked before missing argument",
			args:    []string{"check", "--verbose"},
			wantErr: "unknown option \"--verbose\"",
		},
		{
			name:    "all options are checked before extra arguments",
			args:    []string{"eval", "rules.txt", "flows.txt", "extra.txt", "--verbose"},
			wantErr: "unknown option \"--verbose\"",
		},
		{
			name:    "stdin duplicate is checked after argument count",
			args:    []string{"eval", "-", "-", "extra.txt"},
			wantErr: "too many arguments",
		},
		{
			name:    "stdin cannot be supplied twice",
			args:    []string{"eval", "-", "-"},
			wantErr: "standard input given twice",
		},
		{
			name:    "diff cannot use stdin twice",
			args:    []string{"diff", "-", "-"},
			wantErr: "standard input given twice",
		},
		{
			name: "check accepts stdin marker",
			args: []string{"check", "-"},
			want: invocation{command: "check", files: []string{"-"}},
		},
		{
			name: "eval accepts one stdin marker",
			args: []string{"eval", "-", "flows.txt"},
			want: invocation{command: "eval", files: []string{"-", "flows.txt"}},
		},
		{
			name: "diff accepts one stdin marker",
			args: []string{"diff", "old.txt", "-"},
			want: invocation{command: "diff", files: []string{"old.txt", "-"}},
		},
		{
			name: "check accepts a named file",
			args: []string{"check", "rules.txt"},
			want: invocation{command: "check", files: []string{"rules.txt"}},
		},
		{
			name: "eval accepts two named files",
			args: []string{"eval", "rules.txt", "flows.txt"},
			want: invocation{command: "eval", files: []string{"rules.txt", "flows.txt"}},
		},
		{
			name: "diff accepts two named files",
			args: []string{"diff", "old.txt", "new.txt"},
			want: invocation{command: "diff", files: []string{"old.txt", "new.txt"}},
		},
		{
			name:    "unknown option on second argument",
			args:    []string{"eval", "rules.txt", "--flows"},
			wantErr: "unknown option \"--flows\"",
		},
		{
			name: "bare minus is not an option",
			args: []string{"eval", "-", "flows.txt"},
			want: invocation{command: "eval", files: []string{"-", "flows.txt"}},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, gotHelp, err := parseArgs(tt.args)
			if tt.wantErr != "" {
				if err == nil || err.Error() != tt.wantErr {
					t.Fatalf("parseArgs(%q) error = %v, want %q", tt.args, err, tt.wantErr)
				}
				if gotHelp {
					t.Fatal("parseArgs reported help on an error")
				}
				if !reflect.DeepEqual(got, invocation{}) {
					t.Fatalf("parseArgs(%q) invocation = %#v, want zero value", tt.args, got)
				}
				return
			}
			if err != nil {
				t.Fatalf("parseArgs(%q) error = %v, want nil", tt.args, err)
			}
			if gotHelp != tt.wantHelp {
				t.Fatalf("parseArgs(%q) help = %t, want %t", tt.args, gotHelp, tt.wantHelp)
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Fatalf("parseArgs(%q) invocation = %#v, want %#v", tt.args, got, tt.want)
			}
		})
	}
}

func TestDisplayArgument(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{name: "empty value", input: "", want: ""},
		{name: "printable ASCII boundary is retained", input: "AZaz09!~_-./", want: "AZaz09!~_-./"},
		{name: "space and non-ASCII code points each become question marks", input: "x\té🙂 \x00~", want: "x?????~"},
		{name: "quotes and backslashes are not escaped", input: "\"\\\x7f", want: "\"\\?"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := displayArgument(tt.input); got != tt.want {
				t.Errorf("displayArgument(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

func TestParseArgsDeniedOption(t *testing.T) {
	tests := []struct {
		name    string
		args    []string
		want    invocation
		wantErr string
	}{
		{
			name: "flag before files",
			args: []string{"eval", "--denied", "rules.txt", "flows.txt"},
			want: invocation{command: "eval", files: []string{"rules.txt", "flows.txt"}, deniedOnly: true},
		},
		{
			name: "flag between files",
			args: []string{"eval", "rules.txt", "--denied", "flows.txt"},
			want: invocation{command: "eval", files: []string{"rules.txt", "flows.txt"}, deniedOnly: true},
		},
		{
			name: "flag after files",
			args: []string{"eval", "rules.txt", "flows.txt", "--denied"},
			want: invocation{command: "eval", files: []string{"rules.txt", "flows.txt"}, deniedOnly: true},
		},
		{
			name: "repeated flag has no effect",
			args: []string{"eval", "--denied", "rules.txt", "--denied", "flows.txt", "--denied"},
			want: invocation{command: "eval", files: []string{"rules.txt", "flows.txt"}, deniedOnly: true},
		},
		{
			name:    "check does not accept the flag",
			args:    []string{"check", "--denied", "rules.txt"},
			wantErr: "unknown option \"--denied\"",
		},
		{
			name:    "diff does not accept the flag",
			args:    []string{"diff", "--denied", "old.txt", "new.txt"},
			wantErr: "unknown option \"--denied\"",
		},
		{
			name:    "value spelling is not the flag",
			args:    []string{"eval", "--denied=1", "rules.txt", "flows.txt"},
			wantErr: "unknown option \"--denied=1\"",
		},
		{
			name:    "all value spellings are rejected before argument count",
			args:    []string{"eval", "--denied=yes"},
			wantErr: "unknown option \"--denied=yes\"",
		},
		{
			name:    "flag does not count as a file",
			args:    []string{"eval", "--denied"},
			wantErr: "missing argument",
		},
		{
			name:    "extra positional argument is rejected with flag",
			args:    []string{"eval", "--denied", "rules.txt", "flows.txt", "extra.txt"},
			wantErr: "too many arguments",
		},
		{
			name:    "unknown option precedes missing argument with flag",
			args:    []string{"eval", "--denied", "--verbose"},
			wantErr: "unknown option \"--verbose\"",
		},
		{
			name:    "argument count precedes duplicate stdin with flag",
			args:    []string{"eval", "--denied", "-", "--denied", "-", "extra.txt"},
			wantErr: "too many arguments",
		},
		{
			name:    "stdin cannot be supplied twice with flag",
			args:    []string{"eval", "--denied", "-", "--denied", "-"},
			wantErr: "standard input given twice",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, help, err := parseArgs(tt.args)
			if tt.wantErr != "" {
				if err == nil || err.Error() != tt.wantErr {
					t.Fatalf("parseArgs(%q) error = %v, want %q", tt.args, err, tt.wantErr)
				}
				if help || !reflect.DeepEqual(got, invocation{}) {
					t.Fatalf("parseArgs(%q) returned help %t and invocation %#v on error", tt.args, help, got)
				}
				return
			}
			if err != nil {
				t.Fatalf("parseArgs(%q) error = %v, want nil", tt.args, err)
			}
			if help {
				t.Fatalf("parseArgs(%q) reported help", tt.args)
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Fatalf("parseArgs(%q) invocation = %#v, want %#v", tt.args, got, tt.want)
			}
		})
	}

	t.Run("does not modify caller arguments", func(t *testing.T) {
		args := []string{"eval", "--denied", "rules.txt", "flows.txt"}
		original := append([]string(nil), args...)
		if _, _, err := parseArgs(args); err != nil {
			t.Fatalf("parseArgs(%q) error = %v, want nil", args, err)
		}
		if !reflect.DeepEqual(args, original) {
			t.Fatalf("parseArgs modified arguments to %q, want %q", args, original)
		}
	})
}
