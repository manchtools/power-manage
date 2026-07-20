package good

// encoding/json far from proto types is fine — the guard must not flag
// plain JSON use.

import "encoding/json"

func onlyJSON(v any) ([]byte, error) {
	return json.Marshal(v)
}
