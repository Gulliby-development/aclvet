package cli

import (
	"errors"
	"fmt"
	"strings"
)

type invocation struct {
	command string
	files   []string
}

func parseArgs(args []string) (invocation, bool, error) {
	if len(args) == 1 && args[0] == "--help" {
		return invocation{}, true, nil
	}
	if len(args) == 0 {
		return invocation{}, false, fmt.Errorf("missing command (check, eval or diff)")
	}

	command := args[0]
	required := 0
	switch command {
	case "check":
		required = 1
	case "eval", "diff":
		required = 2
	default:
		return invocation{}, false, errors.New("unknown command \"" + displayArgument(command) + "\"")
	}

	files := args[1:]
	for _, file := range files {
		if strings.HasPrefix(file, "-") && file != "-" {
			return invocation{}, false, errors.New("unknown option \"" + displayArgument(file) + "\"")
		}
	}
	if len(files) < required {
		return invocation{}, false, fmt.Errorf("missing argument")
	}
	if len(files) > required {
		return invocation{}, false, fmt.Errorf("too many arguments")
	}

	stdinCount := 0
	for _, file := range files {
		if file == "-" {
			stdinCount++
		}
	}
	if stdinCount > 1 {
		return invocation{}, false, fmt.Errorf("standard input given twice")
	}

	return invocation{command: command, files: files}, false, nil
}

func displayArgument(value string) string {
	return strings.Map(func(r rune) rune {
		if r < '!' || r > '~' {
			return '?'
		}
		return r
	}, value)
}
