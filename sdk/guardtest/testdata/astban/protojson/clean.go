package protojson

import "google.golang.org/protobuf/encoding/protojson"

// Clean: proto messages marshal through protojson only.
func encodeClean(m interface{ ProtoReflect() any }) ([]byte, error) {
	_ = protojson.MarshalOptions{}
	return nil, nil
}
