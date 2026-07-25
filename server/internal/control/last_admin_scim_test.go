package control

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/manchtools/power-manage/server/internal/store"
)

func TestSCIMStoreError_LastAdminMapsStaticConflict(t *testing.T) {
	response := httptest.NewRecorder()
	(&SCIMService{}).writeSCIMStoreError(response, store.ErrLastAdmin)
	if response.Code != http.StatusConflict {
		t.Fatalf("SCIM last-admin status = %d; want 409", response.Code)
	}
	var body scimErrorResponse
	if err := json.NewDecoder(response.Body).Decode(&body); err != nil {
		t.Fatalf("decode SCIM last-admin response: %v", err)
	}
	if body.Status != "409" ||
		body.Detail != errCRUDFailedPrecondition.Error() {
		t.Fatalf("SCIM last-admin response = %+v; want static conflict", body)
	}
}
