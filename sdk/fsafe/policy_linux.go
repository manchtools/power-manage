//go:build linux

package fsafe

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"time"

	pmexec "github.com/manchtools/power-manage/sdk/exec"
	"github.com/manchtools/power-manage/sdk/rollback"
	"github.com/manchtools/power-manage/sdk/validate"
)

// ErrInvalidPolicyFile marks a malformed policy request or managed block.
var ErrInvalidPolicyFile = errors.New("fsafe: invalid policy file")

// PolicySurface selects one of the closed managed-policy rows in SPEC-004.
// The zero value is invalid.
type PolicySurface uint8

const (
	PolicySurfaceSSH PolicySurface = iota + 1
	PolicySurfaceSSHD
	PolicySurfaceAdminPolicy
)

// PolicyFilePresence makes a whole-file snapshot's presence explicit. The
// zero value is invalid so a partially decoded request cannot mean removal.
type PolicyFilePresence uint8

const (
	PolicyFilePresent PolicyFilePresence = iota + 1
	PolicyFileAbsent
)

// PolicyManagedBlock identifies one exact marker-delimited region. Markers
// are complete lines, must start with the inert "# " prefix, and must be
// distinct and control-free.
type PolicyManagedBlock struct {
	Begin string
	End   string
}

// PolicyFileState is either a whole-file snapshot (Block nil) or a managed
// block operation. A present block inserts/replaces Content; an absent block
// removes it. Previous states returned by ApplyPolicyFile are always complete
// snapshots and can be replayed unchanged through the same method.
type PolicyFileState struct {
	Presence PolicyFilePresence
	Content  []byte
	Block    *PolicyManagedBlock
}

// PolicyFileRequest names the closed surface, target, and desired state.
type PolicyFileRequest struct {
	Surface PolicySurface
	Path    string
	Desired PolicyFileState
}

// PolicyFileResult reports whether the target changed and captures its exact
// prior presence/content for revert-on-unassign.
type PolicyFileResult struct {
	Changed  bool
	Previous PolicyFileState
}

type policyPathClass uint8
type policyValidator uint8
type policyReload uint8

const (
	policyPathSSHDPerAction policyPathClass = iota + 1
	policyPathSSHDGlobal
	policyPathSudoers
)

const (
	policyValidatorSSHD policyValidator = iota + 1
	policyValidatorVisudo
)

const (
	policyReloadSSHD policyReload = iota + 1
	policyReloadNone
)

// Unkeyed rows are deliberate: all three required columns must be supplied or
// this declaration stops compiling (AC-22).
type policySurfaceSpec struct {
	path      policyPathClass
	validator policyValidator
	reload    policyReload
}

// docref: begin policy-surface-table
var policySurfaceTable = [...]policySurfaceSpec{
	{policyPathSSHDPerAction, policyValidatorSSHD, policyReloadSSHD},
	{policyPathSSHDGlobal, policyValidatorSSHD, policyReloadSSHD},
	{policyPathSudoers, policyValidatorVisudo, policyReloadNone},
}

// docref: end policy-surface-table

var policyRootFor = func(pathClass policyPathClass) string {
	switch pathClass {
	case policyPathSSHDPerAction, policyPathSSHDGlobal:
		return "/etc/ssh/sshd_config.d"
	case policyPathSudoers:
		return "/etc/sudoers.d"
	default:
		return ""
	}
}

var policySwapRename = safeRename

const policyRestoreTimeout = 30 * time.Second

// policyCandidateScript creates the validator-visible candidate under the
// same root escalation as its write. Positional parameters keep path/mode out
// of shell source; content travels only on stdin.
const policyCandidateScript = `set -eu
target=$1
mode=$2
dir=$(dirname -- "$target")
tmp=$(mktemp "$dir/.pm-policy-XXXXXXXXXX")
trap 'rm -f -- "$tmp"' EXIT
cat > "$tmp"
chmod -- "$mode" "$tmp"
printf '%s\n' "$tmp"
trap - EXIT
`

// ApplyPolicyFile is the single managed-policy composition ([SDK-18]): render
// the desired whole file, hash-short-circuit, write and validate a random
// candidate, atomically publish/remove it, reload, and restore the exact prior
// snapshot if any post-write step fails.
func (m Manager) ApplyPolicyFile(ctx context.Context, req PolicyFileRequest) (PolicyFileResult, error) {
	if ctx == nil {
		return PolicyFileResult{}, fmt.Errorf("%w: context is required", ErrInvalidPolicyFile)
	}
	row, err := policySurface(req.Surface)
	if err != nil {
		return PolicyFileResult{}, err
	}
	target, err := validatePolicyTarget(req.Path, row.path)
	if err != nil {
		return PolicyFileResult{}, err
	}
	current, err := m.readPolicyState(ctx, target)
	if err != nil {
		return PolicyFileResult{}, err
	}
	desired, err := renderPolicyState(req.Desired, current, row.validator)
	if err != nil {
		return PolicyFileResult{}, err
	}
	previous := clonePolicyState(current)
	if samePolicyState(current, desired) {
		return PolicyFileResult{Previous: previous}, nil
	}

	var candidate string
	mode := policyFileMode(row.path)
	// docref: begin policy-transaction
	err = rollback.Run(ctx,
		rollback.Step{
			Name: "write policy candidate",
			Apply: func(stepCtx context.Context) error {
				var createErr error
				candidate, createErr = m.createPolicyCandidate(stepCtx, target, desired.Content, mode)
				return createErr
			},
			Rollback: func(stepCtx context.Context) error {
				if candidate == "" {
					return nil
				}
				return m.Remove(stepCtx, candidate)
			},
		},
		rollback.Step{
			Name: "validate policy candidate",
			Apply: func(stepCtx context.Context) error {
				return m.validatePolicyCandidate(stepCtx, row.validator, candidate)
			},
			Rollback: func(context.Context) error { return nil },
		},
		rollback.Step{
			Name: "discard absence candidate",
			Apply: func(stepCtx context.Context) error {
				if desired.Presence != PolicyFileAbsent {
					return nil
				}
				if removeErr := m.Remove(stepCtx, candidate); removeErr != nil {
					return removeErr
				}
				candidate = ""
				return nil
			},
			Rollback: func(context.Context) error { return nil },
		},
		rollback.Step{
			Name: "swap policy file",
			Apply: func(stepCtx context.Context) error {
				var swapErr error
				if desired.Presence == PolicyFileAbsent {
					swapErr = m.Remove(stepCtx, target)
				} else {
					swapErr = m.swapPolicyCandidate(stepCtx, candidate, target)
				}
				if swapErr != nil {
					restoreCtx, cancel := context.WithTimeout(context.WithoutCancel(stepCtx), policyRestoreTimeout)
					restoreErr := m.restorePolicyState(restoreCtx, target, current, mode)
					cancel()
					if restoreErr != nil {
						return errors.Join(swapErr, fmt.Errorf("restore policy after failed swap: %w", restoreErr))
					}
					return swapErr
				}
				candidate = ""
				return nil
			},
			Rollback: func(stepCtx context.Context) error {
				return m.restorePolicyState(stepCtx, target, current, mode)
			},
		},
		rollback.Step{
			Name: "reload policy surface",
			Apply: func(stepCtx context.Context) error {
				return m.reloadPolicySurface(stepCtx, row.reload)
			},
			Rollback: func(context.Context) error { return nil },
		},
	)
	// docref: end policy-transaction
	if err != nil {
		return PolicyFileResult{}, err
	}
	return PolicyFileResult{Changed: true, Previous: previous}, nil
}

func policySurface(surface PolicySurface) (policySurfaceSpec, error) {
	if surface < PolicySurfaceSSH || int(surface) > len(policySurfaceTable) {
		return policySurfaceSpec{}, fmt.Errorf("%w: unknown surface %d", ErrInvalidPolicyFile, surface)
	}
	return policySurfaceTable[int(surface)-1], nil
}

func validatePolicyTarget(path string, pathClass policyPathClass) (string, error) {
	if err := ValidatePath(path); err != nil {
		return "", fmt.Errorf("%w: %w", ErrInvalidPolicyFile, err)
	}
	if !filepath.IsAbs(path) {
		return "", fmt.Errorf("%w: target is not absolute", ErrInvalidPolicyFile)
	}
	literal := filepath.Clean(path)
	root := filepath.Clean(policyRootFor(pathClass))
	if root == "." || !filepath.IsAbs(root) || filepath.Dir(literal) != root {
		return "", fmt.Errorf("%w: target is outside its surface path class", ErrInvalidPolicyFile)
	}
	if err := validatePolicyFilename(pathClass, filepath.Base(literal)); err != nil {
		return "", err
	}
	if err := parentDirSafe(root); err != nil {
		return "", err
	}
	if info, err := os.Lstat(literal); err == nil {
		if info.Mode()&os.ModeSymlink != 0 {
			return "", fmt.Errorf("%w: target is a symlink", ErrInvalidPolicyFile)
		}
	} else if !errors.Is(err, fs.ErrNotExist) {
		return "", fmt.Errorf("inspect policy target: %w", err)
	}
	resolvedRoot, err := ResolveAndValidatePath(root)
	if err != nil {
		return "", fmt.Errorf("%w: resolve surface root: %w", ErrInvalidPolicyFile, err)
	}
	resolvedTarget, err := ResolveAndValidatePath(literal)
	if err != nil {
		return "", fmt.Errorf("%w: resolve target: %w", ErrInvalidPolicyFile, err)
	}
	if filepath.Dir(resolvedTarget) != resolvedRoot {
		return "", fmt.Errorf("%w: resolved target escapes its surface path class", ErrInvalidPolicyFile)
	}
	return resolvedTarget, nil
}

func validatePolicyFilename(pathClass policyPathClass, name string) error {
	validName := func(allowDot bool) bool {
		if name == "" || !isPolicyNameAlnum(name[0]) {
			return false
		}
		for i := 1; i < len(name); i++ {
			if isPolicyNameAlnum(name[i]) || name[i] == '-' || name[i] == '_' || allowDot && name[i] == '.' {
				continue
			}
			return false
		}
		return true
	}
	switch pathClass {
	case policyPathSSHDPerAction, policyPathSSHDGlobal:
		if validName(true) && strings.HasSuffix(name, ".conf") {
			return nil
		}
	case policyPathSudoers:
		if validName(false) {
			return nil
		}
	}
	return fmt.Errorf("%w: target filename is not effective for its surface", ErrInvalidPolicyFile)
}

func isPolicyNameAlnum(b byte) bool {
	return b >= 'a' && b <= 'z' || b >= 'A' && b <= 'Z' || b >= '0' && b <= '9'
}

func policyFileMode(pathClass policyPathClass) os.FileMode {
	if pathClass == policyPathSudoers {
		return 0o440
	}
	return 0o644
}

func (m Manager) readPolicyState(ctx context.Context, path string) (PolicyFileState, error) {
	content, err := m.ReadFile(ctx, path)
	if errors.Is(err, fs.ErrNotExist) {
		return PolicyFileState{Presence: PolicyFileAbsent}, nil
	}
	if err != nil {
		return PolicyFileState{}, fmt.Errorf("read policy file: %w", err)
	}
	return PolicyFileState{Presence: PolicyFilePresent, Content: bytes.Clone(content)}, nil
}

func clonePolicyState(state PolicyFileState) PolicyFileState {
	return PolicyFileState{Presence: state.Presence, Content: bytes.Clone(state.Content)}
}

func samePolicyState(a, b PolicyFileState) bool {
	if a.Presence != b.Presence {
		return false
	}
	if a.Presence == PolicyFileAbsent {
		return true
	}
	return sha256.Sum256(a.Content) == sha256.Sum256(b.Content)
}

func renderPolicyState(desired, current PolicyFileState, validator policyValidator) (PolicyFileState, error) {
	if desired.Presence != PolicyFilePresent && desired.Presence != PolicyFileAbsent {
		return PolicyFileState{}, fmt.Errorf("%w: desired presence is required", ErrInvalidPolicyFile)
	}
	if desired.Block == nil {
		if desired.Presence == PolicyFileAbsent && len(desired.Content) != 0 {
			return PolicyFileState{}, fmt.Errorf("%w: absent whole file carries content", ErrInvalidPolicyFile)
		}
		return PolicyFileState{Presence: desired.Presence, Content: bytes.Clone(desired.Content)}, nil
	}
	if desired.Presence == PolicyFileAbsent && len(desired.Content) != 0 {
		return PolicyFileState{}, fmt.Errorf("%w: absent managed block carries content", ErrInvalidPolicyFile)
	}
	if err := validatePolicyMarkers(*desired.Block, validator); err != nil {
		return PolicyFileState{}, err
	}
	if len(policyMarkerSpans(desired.Content, desired.Block.Begin)) != 0 || len(policyMarkerSpans(desired.Content, desired.Block.End)) != 0 {
		return PolicyFileState{}, fmt.Errorf("%w: managed content contains a block marker", ErrInvalidPolicyFile)
	}
	content, err := renderPolicyBlock(current, desired)
	if err != nil {
		return PolicyFileState{}, err
	}
	if current.Presence == PolicyFileAbsent && desired.Presence == PolicyFileAbsent {
		return PolicyFileState{Presence: PolicyFileAbsent}, nil
	}
	return PolicyFileState{Presence: PolicyFilePresent, Content: content}, nil
}

func validatePolicyMarkers(block PolicyManagedBlock, validator policyValidator) error {
	if block.Begin == "" || block.End == "" || block.Begin == block.End {
		return fmt.Errorf("%w: managed-block markers must be non-empty and distinct", ErrInvalidPolicyFile)
	}
	if !strings.HasPrefix(block.Begin, "# ") || !strings.HasPrefix(block.End, "# ") {
		return fmt.Errorf("%w: managed-block markers must be comment lines", ErrInvalidPolicyFile)
	}
	validateLine := validate.SSHDConfigValue
	if validator == policyValidatorVisudo {
		validateLine = validate.SudoersValue
	}
	if err := validateLine(block.Begin); err != nil {
		return fmt.Errorf("%w: invalid begin marker", ErrInvalidPolicyFile)
	}
	if err := validateLine(block.End); err != nil {
		return fmt.Errorf("%w: invalid end marker", ErrInvalidPolicyFile)
	}
	return nil
}

type policyMarkerSpan struct {
	start int
	end   int
}

func policyMarkerSpans(content []byte, marker string) []policyMarkerSpan {
	var spans []policyMarkerSpan
	for start := 0; start <= len(content); {
		relEnd := bytes.IndexByte(content[start:], '\n')
		end := len(content)
		lineEnd := end
		if relEnd >= 0 {
			lineEnd = start + relEnd
			end = lineEnd + 1
		}
		if bytes.Equal(content[start:lineEnd], []byte(marker)) {
			spans = append(spans, policyMarkerSpan{start: start, end: end})
		}
		if relEnd < 0 {
			break
		}
		start = end
	}
	return spans
}

func renderPolicyBlock(current, desired PolicyFileState) ([]byte, error) {
	block := *desired.Block
	begins := policyMarkerSpans(current.Content, block.Begin)
	ends := policyMarkerSpans(current.Content, block.End)
	if len(begins) == 0 && len(ends) == 0 {
		if desired.Presence == PolicyFileAbsent {
			return bytes.Clone(current.Content), nil
		}
		out := bytes.Clone(current.Content)
		if len(out) > 0 && out[len(out)-1] != '\n' {
			out = append(out, '\n')
		}
		return append(out, policyBlockBytes(block, desired.Content)...), nil
	}
	if len(begins) != 1 || len(ends) != 1 || begins[0].start >= ends[0].start {
		return nil, fmt.Errorf("%w: managed-block markers are missing, duplicated, or out of order", ErrInvalidPolicyFile)
	}
	if desired.Presence == PolicyFileAbsent {
		out := append(bytes.Clone(current.Content[:begins[0].start]), current.Content[ends[0].end:]...)
		return out, nil
	}
	out := bytes.Clone(current.Content[:begins[0].start])
	out = append(out, policyBlockBytes(block, desired.Content)...)
	out = append(out, current.Content[ends[0].end:]...)
	return out, nil
}

func policyBlockBytes(block PolicyManagedBlock, content []byte) []byte {
	out := make([]byte, 0, len(block.Begin)+len(block.End)+len(content)+3)
	out = append(out, block.Begin...)
	out = append(out, '\n')
	out = append(out, content...)
	if len(content) > 0 && content[len(content)-1] != '\n' {
		out = append(out, '\n')
	}
	out = append(out, block.End...)
	out = append(out, '\n')
	return out
}

func (m Manager) createPolicyCandidate(ctx context.Context, target string, content []byte, mode os.FileMode) (string, error) {
	if err := parentDirSafe(filepath.Dir(target)); err != nil {
		return "", err
	}
	if m.direct() {
		candidate, err := writeTempFrom(target, bytes.NewReader(content), mode)
		if err != nil {
			return "", fmt.Errorf("write policy candidate: %w", err)
		}
		return candidate, nil
	}
	res, err := m.r.Run(ctx, pmexec.Command{
		Name:     "sh",
		Args:     []string{"-c", policyCandidateScript, "sh", target, modeArg(mode)},
		Stdin:    bytes.NewReader(content),
		Escalate: true,
	})
	if err != nil {
		return "", err
	}
	if res.ExitCode != 0 {
		return "", cmdErr("sh", res)
	}
	candidate := strings.TrimSuffix(res.Stdout, "\n")
	if candidate == "" || strings.ContainsAny(candidate, "\r\n\x00") || filepath.Dir(candidate) != filepath.Dir(target) || !strings.HasPrefix(filepath.Base(candidate), ".pm-policy-") {
		return "", fmt.Errorf("%w: candidate writer returned an invalid path", ErrInvalidPolicyFile)
	}
	if err := ValidatePath(candidate); err != nil {
		return "", fmt.Errorf("%w: candidate writer returned an invalid path", ErrInvalidPolicyFile)
	}
	return candidate, nil
}

func (m Manager) validatePolicyCandidate(ctx context.Context, validator policyValidator, candidate string) error {
	var name string
	var args []string
	switch validator {
	case policyValidatorSSHD:
		name, args = "sshd", []string{"-t", "-f", candidate}
	case policyValidatorVisudo:
		name, args = "visudo", []string{"-c", "-f", candidate}
	default:
		return fmt.Errorf("%w: unknown validator %d", ErrInvalidPolicyFile, validator)
	}
	res, err := m.run(ctx, name, args...)
	if err != nil {
		return err
	}
	if res.ExitCode != 0 {
		return cmdErr(name, res)
	}
	return nil
}

func (m Manager) swapPolicyCandidate(ctx context.Context, candidate, target string) error {
	if candidate == "" || filepath.Dir(candidate) != filepath.Dir(target) {
		return fmt.Errorf("%w: candidate is not a target sibling", ErrInvalidPolicyFile)
	}
	if err := parentDirSafe(filepath.Dir(target)); err != nil {
		return err
	}
	if m.direct() {
		return policySwapRename(candidate, target, true)
	}
	res, err := m.run(ctx, "mv", "-T", "--", candidate, target)
	if err != nil {
		return err
	}
	if res.ExitCode != 0 {
		return cmdErr("mv", res)
	}
	return nil
}

func (m Manager) reloadPolicySurface(ctx context.Context, reload policyReload) error {
	switch reload {
	case policyReloadNone:
		return nil
	case policyReloadSSHD:
		res, err := m.run(ctx, "systemctl", "reload", "sshd")
		if err != nil {
			return err
		}
		if res.ExitCode != 0 {
			return cmdErr("systemctl", res)
		}
		return nil
	default:
		return fmt.Errorf("%w: unknown reload %d", ErrInvalidPolicyFile, reload)
	}
}

func (m Manager) restorePolicyState(ctx context.Context, target string, state PolicyFileState, mode os.FileMode) error {
	if state.Presence == PolicyFileAbsent {
		return m.Remove(ctx, target)
	}
	return m.WriteFile(ctx, target, state.Content, WriteOptions{Mode: mode})
}
