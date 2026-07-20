package exec

import (
	"context"
	"reflect"
	"strings"
	"testing"
)

// TestSeparatePositionals_InsertsEndOfOptions pins the core [SDK-4]/AC-5
// contract: the "--" end-of-options token is always inserted between the
// flags and the positional operands, so a flag-shaped operand (a package
// name like "-e", a remote like "--from") can never be reparsed by the
// invoked program as an option.
func TestSeparatePositionals_InsertsEndOfOptions(t *testing.T) {
	cases := []struct {
		name        string
		flags       []string
		positionals []string
		want        []string
	}{
		{
			name:        "rpm query",
			flags:       []string{"-q"},
			positionals: []string{"bash"},
			want:        []string{"-q", "--", "bash"},
		},
		{
			name:        "rpm erase with flag-shaped name stays an operand",
			flags:       []string{"-e"},
			positionals: []string{"--eval=evil"},
			want:        []string{"-e", "--", "--eval=evil"},
		},
		{
			name:        "flatpak install with remote+appid",
			flags:       []string{"install", "-y", "--noninteractive", "--system"},
			positionals: []string{"flathub", "org.videolan.VLC"},
			want:        []string{"install", "-y", "--noninteractive", "--system", "--", "flathub", "org.videolan.VLC"},
		},
		{
			name:        "no flags",
			flags:       nil,
			positionals: []string{"x"},
			want:        []string{"--", "x"},
		},
		{
			name:        "no positionals still terminates options",
			flags:       []string{"-q"},
			positionals: nil,
			want:        []string{"-q", "--"},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := SeparatePositionals(tc.flags, tc.positionals...)
			if !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("SeparatePositionals(%v, %v) = %v, want %v", tc.flags, tc.positionals, got, tc.want)
			}
			// The "--" must sit before every positional: its index must
			// be strictly less than the index of any operand.
			sep := -1
			for i, a := range got {
				if a == EndOfOptions {
					sep = i
					break
				}
			}
			if sep < 0 {
				t.Fatalf("result %v contains no %q separator", got, EndOfOptions)
			}
			for _, p := range tc.positionals {
				idx := -1
				for i := sep + 1; i < len(got); i++ {
					if got[i] == p {
						idx = i
						break
					}
				}
				if idx < 0 {
					t.Errorf("positional %q does not appear after the %q separator", p, EndOfOptions)
				}
			}
		})
	}
}

// TestSeparatePositionals_DoesNotMutateFlags guards against the helper
// aliasing/appending into the caller's flags slice — a classic
// append-to-shared-backing-array bug that would corrupt a reused flag
// list across calls.
func TestSeparatePositionals_DoesNotMutateFlags(t *testing.T) {
	flags := []string{"-q"}
	_ = SeparatePositionals(flags, "bash")
	_ = SeparatePositionals(flags, "curl")
	if !reflect.DeepEqual(flags, []string{"-q"}) {
		t.Fatalf("input flags were mutated: %v", flags)
	}
}

// AC-5 end-to-end: an operand beginning with "-" is passed VERBATIM as an
// operand through the real Runner — it reaches the child's argv unchanged,
// after the "--" separator, never reinterpreted (there is no shell in
// between; the Runner's API is argv-only by construction).
func TestRunner_DashOperandPassesVerbatim(t *testing.T) {
	dir := t.TempDir()
	tool := writeExecScript(t, dir, "tool", "#!/bin/sh\nfor a in \"$@\"; do printf 'ARG:%s\\n' \"$a\"; done\n")

	res, err := directRunner(t).Run(context.Background(), Command{
		Name: tool,
		Args: SeparatePositionals([]string{"-q"}, "-rf"),
	})
	if err != nil {
		t.Fatalf("Run err = %v", err)
	}
	want := "ARG:-q\nARG:--\nARG:-rf\n"
	if res.Stdout != want {
		t.Errorf("child argv rendering = %q, want %q (dash operand verbatim after --)", res.Stdout, want)
	}
	if !strings.Contains(res.Stdout, "ARG:-rf\n") {
		t.Errorf("operand -rf did not reach the child verbatim: %q", res.Stdout)
	}
}
