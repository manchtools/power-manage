package cap

// Clean: OS mechanism imports stay untouched.
import (
	"os"
	"os/exec"
)

var _ = os.Getenv
var _ = exec.Command
