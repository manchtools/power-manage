package cap

// Planted violations: proto runtime, connect, and the generated contract.
import (
	_ "connectrpc.com/connect"
	_ "github.com/manchtools/power-manage/contract/gen/pm/v1"
	_ "google.golang.org/protobuf/proto"
)
