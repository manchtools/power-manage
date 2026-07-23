package control

import (
	"encoding/json"
	"net/http"
)

func writeOIDCTestJSON(response http.ResponseWriter, value any) error {
	encoded, err := marshalOIDCTestJSON(value)
	if err != nil {
		return err
	}
	_, err = response.Write(append(encoded, '\n'))
	return err
}

func marshalOIDCTestJSON(value any) ([]byte, error) {
	return json.Marshal(value)
}
