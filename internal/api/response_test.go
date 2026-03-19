package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestWriteJSON(t *testing.T) {
	t.Helper()

	rec := httptest.NewRecorder()
	data := map[string]string{"hello": "world"}

	writeJSON(rec, http.StatusOK, data)

	if got, want := rec.Code, http.StatusOK; got != want {
		t.Errorf("status code: got %d, want %d", got, want)
	}
	if got, want := rec.Header().Get("Content-Type"), "application/json"; got != want {
		t.Errorf("Content-Type: got %q, want %q", got, want)
	}

	var resp Response
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatalf("decode response body: %v", err)
	}
	if resp.Error != nil {
		t.Errorf("Error: got %+v, want nil", resp.Error)
	}

	// Data is decoded as map[string]interface{} by encoding/json.
	dataMap, ok := resp.Data.(map[string]interface{})
	if !ok {
		t.Fatalf("Data type: got %T, want map[string]interface{}", resp.Data)
	}
	if got, want := dataMap["hello"], "world"; got != want {
		t.Errorf("Data[hello]: got %v, want %v", got, want)
	}
}

func TestWriteJSON_StatusCodes(t *testing.T) {
	t.Helper()

	tests := []struct {
		name   string
		status int
	}{
		{name: "200 OK", status: http.StatusOK},
		{name: "201 Created", status: http.StatusCreated},
		{name: "204 No Content", status: http.StatusNoContent},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rec := httptest.NewRecorder()
			writeJSON(rec, tt.status, nil)
			if got, want := rec.Code, tt.status; got != want {
				t.Errorf("status code: got %d, want %d", got, want)
			}
		})
	}
}

func TestWriteError(t *testing.T) {
	t.Helper()

	rec := httptest.NewRecorder()
	writeError(rec, http.StatusBadRequest, "BAD_REQUEST", "something went wrong")

	if got, want := rec.Code, http.StatusBadRequest; got != want {
		t.Errorf("status code: got %d, want %d", got, want)
	}
	if got, want := rec.Header().Get("Content-Type"), "application/json"; got != want {
		t.Errorf("Content-Type: got %q, want %q", got, want)
	}

	var resp Response
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatalf("decode response body: %v", err)
	}
	if resp.Data != nil {
		t.Errorf("Data: got %v, want nil", resp.Data)
	}
	if resp.Error == nil {
		t.Fatal("Error: got nil, want non-nil")
	}
	if got, want := resp.Error.Code, "BAD_REQUEST"; got != want {
		t.Errorf("Error.Code: got %q, want %q", got, want)
	}
	if got, want := resp.Error.Message, "something went wrong"; got != want {
		t.Errorf("Error.Message: got %q, want %q", got, want)
	}
}

func TestWriteError_StatusCodes(t *testing.T) {
	t.Helper()

	tests := []struct {
		name   string
		status int
	}{
		{name: "400 Bad Request", status: http.StatusBadRequest},
		{name: "401 Unauthorized", status: http.StatusUnauthorized},
		{name: "403 Forbidden", status: http.StatusForbidden},
		{name: "404 Not Found", status: http.StatusNotFound},
		{name: "500 Internal Server Error", status: http.StatusInternalServerError},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rec := httptest.NewRecorder()
			writeError(rec, tt.status, "CODE", "msg")
			if got, want := rec.Code, tt.status; got != want {
				t.Errorf("status code: got %d, want %d", got, want)
			}
		})
	}
}
