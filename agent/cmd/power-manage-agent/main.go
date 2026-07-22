package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"

	"golang.org/x/term"

	"github.com/manchtools/power-manage/agent/internal/enroll"
	"github.com/manchtools/power-manage/sdk/config"
)

const (
	maxTokenInputBytes = 512
	agentConfigPath    = "/etc/power-manage/agent.conf"
)

type agentConfig struct {
	Enrollment agentEnrollmentConfig
}

type agentEnrollmentConfig struct {
	Socket string `doc:"Absolute path of the local token-authorized enrollment relay socket."`
}

type terminalInput struct {
	isTerminal   func(int) bool
	readPassword func(int) ([]byte, error)
}

type submitEnrollment func(context.Context, string, string, string) (string, error)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	settings := agentConfig{Enrollment: agentEnrollmentConfig{Socket: enroll.DefaultSocketPath}}
	if err := config.Load(agentConfigPath, &settings); err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "power-manage-agent: load configuration: %v\n", err)
		os.Exit(1)
	}
	err := run(
		ctx,
		os.Args[1:],
		os.Stdin,
		os.Stdout,
		os.Stderr,
		int(os.Stdin.Fd()),
		terminalInput{isTerminal: term.IsTerminal, readPassword: term.ReadPassword},
		enroll.Submit,
		settings.Enrollment.Socket,
	)
	if err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "power-manage-agent: %v\n", err)
		os.Exit(1)
	}
}

func run(
	ctx context.Context,
	args []string,
	stdin io.Reader,
	stdout io.Writer,
	stderr io.Writer,
	stdinFD int,
	terminal terminalInput,
	submit submitEnrollment,
	defaultSocket string,
) error {
	if ctx == nil {
		return errors.New("nil command context")
	}
	if stdin == nil || stdout == nil || stderr == nil || terminal.isTerminal == nil || terminal.readPassword == nil || submit == nil || defaultSocket == "" {
		return errors.New("enroll command is not wired")
	}
	if !filepath.IsAbs(defaultSocket) {
		return errors.New("configured enrollment socket path must be absolute")
	}
	if len(args) == 0 || args[0] != "enroll" {
		return errors.New("usage: power-manage-agent enroll [--token-file PATH] [--ca-fingerprint SHA256] [--socket PATH]")
	}
	flags := flag.NewFlagSet("power-manage-agent enroll", flag.ContinueOnError)
	flags.SetOutput(stderr)
	tokenFile := flags.String("token-file", "", "read the registration token from a file")
	caFingerprint := flags.String("ca-fingerprint", "", "require the enrollment CA SHA-256 fingerprint")
	socket := flags.String("socket", defaultSocket, "local agent enrollment socket")
	if err := flags.Parse(args[1:]); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return errors.New("enroll command accepts no positional arguments")
	}
	if !filepath.IsAbs(*socket) {
		return errors.New("enrollment socket path must be absolute")
	}
	var tokenValue string
	var err error
	switch {
	case *tokenFile != "":
		tokenValue, err = readTokenFile(*tokenFile)
	case terminal.isTerminal(stdinFD):
		if _, err := fmt.Fprint(stderr, "Registration token: "); err != nil {
			return fmt.Errorf("write token prompt: %w", err)
		}
		password, readErr := terminal.readPassword(stdinFD)
		_, newlineErr := fmt.Fprintln(stderr)
		if readErr != nil {
			return fmt.Errorf("read registration token from terminal: %w", readErr)
		}
		if newlineErr != nil {
			return fmt.Errorf("finish token prompt: %w", newlineErr)
		}
		tokenValue, err = normalizeTokenInput(password)
	default:
		tokenValue, err = readToken(stdin)
	}
	if err != nil {
		return err
	}
	deviceID, err := submit(ctx, *socket, tokenValue, *caFingerprint)
	if err != nil {
		return fmt.Errorf("enrollment failed: %w", err)
	}
	if _, err := fmt.Fprintf(stdout, "enrolled device %s\n", deviceID); err != nil {
		return fmt.Errorf("write enrollment result: %w", err)
	}
	return nil
}

func readTokenFile(path string) (string, error) {
	file, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK|syscall.O_CLOEXEC, 0)
	if err != nil {
		return "", fmt.Errorf("open token file: %w", err)
	}
	defer func() { _ = file.Close() }()
	info, err := file.Stat()
	if err != nil {
		return "", fmt.Errorf("stat token file: %w", err)
	}
	if !info.Mode().IsRegular() {
		return "", errors.New("token file is not a regular file")
	}
	if info.Mode().Perm()&0o077 != 0 {
		return "", errors.New("token file permissions allow group or other access")
	}
	return readToken(file)
}

func readToken(reader io.Reader) (string, error) {
	if reader == nil {
		return "", errors.New("registration token input is not wired")
	}
	data, err := io.ReadAll(io.LimitReader(reader, maxTokenInputBytes+2))
	if err != nil {
		return "", fmt.Errorf("read registration token: %w", err)
	}
	return normalizeTokenInput(data)
}

func normalizeTokenInput(data []byte) (string, error) {
	value := strings.TrimSpace(string(data))
	if value == "" {
		return "", errors.New("registration token is empty")
	}
	if len(value) > maxTokenInputBytes || len(data) > maxTokenInputBytes+1 {
		return "", fmt.Errorf("registration token input is too large (maximum %d bytes)", maxTokenInputBytes)
	}
	if strings.ContainsAny(value, " \t\r\n") {
		return "", errors.New("registration token contains whitespace")
	}
	return value, nil
}
