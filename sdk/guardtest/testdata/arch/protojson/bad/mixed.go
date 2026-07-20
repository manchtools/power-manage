package bad

// Planted G-6 violation: encoding/json next to generated contract types.

import (
	"encoding/json"

	pmv1 "github.com/manchtools/power-manage/contract/gen/go/powermanage/v1"
)

func mixed(m *pmv1.Fixture) ([]byte, error) {
	return json.Marshal(m)
}
