package protojson

import "encoding/json"

// Planted violation: stdlib encoding/json import — proto messages must go
// through protojson (INV-16); the ban is import-level.
func encode(v any) ([]byte, error) { return json.Marshal(v) }
