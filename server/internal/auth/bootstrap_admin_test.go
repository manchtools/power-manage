package auth

import (
	"errors"
	"go/ast"
	"go/parser"
	"go/token"
	"testing"

	"github.com/manchtools/power-manage/sdk/guardtest"
)

func TestCanonicalBootstrapLoginURL_AllowsHTTPSAndExplicitLoopbackHTTP(t *testing.T) {
	for _, raw := range []string{
		"https://control.example.test/break-glass",
		"http://localhost:8081/break-glass",
		"http://127.0.0.1:8081/break-glass",
		"http://[::1]:8081/break-glass",
	} {
		parsed, err := canonicalBootstrapLoginURL(raw)
		if err != nil {
			t.Fatalf("canonicalBootstrapLoginURL(%q): %v", raw, err)
		}
		if parsed.String() != raw {
			t.Fatalf("canonicalBootstrapLoginURL(%q) = %q; want unchanged", raw, parsed)
		}
	}
}

func TestCanonicalBootstrapLoginURL_RejectsCredentialsQueryFragmentAndRemoteHTTP(t *testing.T) {
	for _, raw := range []string{
		"",
		"https://user:secret@control.example.test/break-glass",
		"https://control.example.test/break-glass?token=secret",
		"https://control.example.test/break-glass#existing",
		"http://control.example.test/break-glass",
		"ftp://control.example.test/break-glass",
		"https:///missing-host",
	} {
		if _, err := canonicalBootstrapLoginURL(raw); !errors.Is(err, ErrBootstrapRejected) {
			t.Fatalf(
				"canonicalBootstrapLoginURL(%q) error = %v; want %v",
				raw,
				err,
				ErrBootstrapRejected,
			)
		}
	}
}

func TestCanonicalBootstrapToken_TrimsThenRequiresCanonical256BitSecret(t *testing.T) {
	const token = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8"
	if got, ok := canonicalBootstrapToken(" \t" + token + "\n"); !ok || got != token {
		t.Fatalf("canonical bootstrap token = (%q, %t); want trimmed canonical token", got, ok)
	}
	for _, raw := range []string{
		"",
		"not-base64",
		token + "=",
		"AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHg",
	} {
		if got, ok := canonicalBootstrapToken(raw); ok || got != "" {
			t.Fatalf("canonicalBootstrapToken(%q) = (%q, %t); want rejection", raw, got, ok)
		}
	}
}

func TestGuard_BootstrapConsumeUsesOnlyVersionPinnedAppend(t *testing.T) {
	consumers := guardtest.Discover(t, "bootstrap admin consumer methods", 1, func() ([]*ast.FuncDecl, error) {
		fileset := token.NewFileSet()
		file, err := parser.ParseFile(fileset, "bootstrap_admin.go", nil, 0)
		if err != nil {
			return nil, err
		}
		var discovered []*ast.FuncDecl
		for _, declaration := range file.Decls {
			function, ok := declaration.(*ast.FuncDecl)
			if !ok ||
				function.Name.Name != "Consume" ||
				function.Recv == nil ||
				len(function.Recv.List) != 1 {
				continue
			}
			pointer, ok := function.Recv.List[0].Type.(*ast.StarExpr)
			if !ok {
				continue
			}
			receiver, ok := pointer.X.(*ast.Ident)
			if ok && receiver.Name == "BootstrapAdminConsumer" {
				discovered = append(discovered, function)
			}
		}
		return discovered, nil
	})
	if len(consumers) != 1 {
		t.Fatalf("bootstrap admin consumer methods = %d; want exactly one", len(consumers))
	}
	calls := map[string]int{}
	ast.Inspect(consumers[0].Body, func(node ast.Node) bool {
		call, ok := node.(*ast.CallExpr)
		if !ok {
			return true
		}
		selector, ok := call.Fun.(*ast.SelectorExpr)
		if ok {
			calls[selector.Sel.Name]++
		}
		return true
	})
	if calls["AppendEventWithVersion"] != 1 || calls["AppendEvent"] != 0 {
		t.Fatalf(
			"bootstrap consume append calls = version-pinned %d, auto-versioned %d; want (1, 0)",
			calls["AppendEventWithVersion"],
			calls["AppendEvent"],
		)
	}
}
