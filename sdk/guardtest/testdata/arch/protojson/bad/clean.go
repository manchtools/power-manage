package bad

// Planted non-violation in the violating package: protojson beside the
// generated types is exactly the sanctioned combination.

import (
	pmv1 "github.com/manchtools/power-manage/contract/gen/go/powermanage/v1"
	"google.golang.org/protobuf/encoding/protojson"
)

func clean(m *pmv1.Fixture) ([]byte, error) {
	return protojson.Marshal(m)
}
