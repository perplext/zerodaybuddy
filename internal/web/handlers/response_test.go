package handlers

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/perplext/zerodaybuddy/pkg/utils"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func newTestLogger() *utils.Logger {
	return utils.NewLogger("", false)
}

// -- writeJSON --

func TestWriteJSON_HappyPath(t *testing.T) {
	w := httptest.NewRecorder()
	payload := map[string]any{"name": "alpha", "n": 42}

	writeJSON(w, http.StatusOK, payload, newTestLogger())

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, "application/json; charset=utf-8", w.Header().Get("Content-Type"))

	var got map[string]any
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &got))
	assert.Equal(t, "alpha", got["name"])
	assert.EqualValues(t, 42, got["n"])
}

func TestWriteJSON_NilValueWritesJSONNull(t *testing.T) {
	w := httptest.NewRecorder()
	writeJSON(w, http.StatusOK, nil, newTestLogger())

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, "null", strings.TrimSpace(w.Body.String()))
}

func TestWriteJSON_NonEncodableTypeStillWritesStatus(t *testing.T) {
	w := httptest.NewRecorder()
	// Channels are not JSON-encodable; encoding errors after WriteHeader
	// has already fired. The status should still reflect what was set.
	writeJSON(w, http.StatusAccepted, make(chan int), newTestLogger())

	assert.Equal(t, http.StatusAccepted, w.Code,
		"status header is written before encoding attempt; must reflect the requested status")
}

func TestWriteJSON_StatusVariants(t *testing.T) {
	for _, status := range []int{
		http.StatusOK,
		http.StatusCreated,
		http.StatusNoContent,
		http.StatusInternalServerError,
	} {
		w := httptest.NewRecorder()
		writeJSON(w, status, struct{}{}, newTestLogger())
		assert.Equal(t, status, w.Code, "status %d", status)
	}
}

// -- writeError --

func TestWriteError_StructureMatchesEnvelope(t *testing.T) {
	w := httptest.NewRecorder()
	writeError(w, http.StatusNotFound, ErrCodeNotFound, "project xyz not found", newTestLogger())

	assert.Equal(t, http.StatusNotFound, w.Code)
	assert.Equal(t, "application/json; charset=utf-8", w.Header().Get("Content-Type"))

	var got ErrorResponse
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &got))
	assert.Equal(t, ErrCodeNotFound, got.Error.Code)
	assert.Equal(t, "project xyz not found", got.Error.Message)
}

func TestWriteError_AcrossStandardCodes(t *testing.T) {
	cases := []struct {
		status int
		code   string
	}{
		{http.StatusBadRequest, ErrCodeInvalidBody},
		{http.StatusBadRequest, ErrCodeInvalidField},
		{http.StatusUnauthorized, ErrCodeUnauthorized},
		{http.StatusForbidden, ErrCodeForbidden},
		{http.StatusConflict, ErrCodeConflict},
		{http.StatusInternalServerError, ErrCodeInternal},
	}
	for _, c := range cases {
		t.Run(c.code, func(t *testing.T) {
			w := httptest.NewRecorder()
			writeError(w, c.status, c.code, "some message", newTestLogger())
			assert.Equal(t, c.status, w.Code)

			var got ErrorResponse
			require.NoError(t, json.Unmarshal(w.Body.Bytes(), &got))
			assert.Equal(t, c.code, got.Error.Code)
		})
	}
}

// -- decodeJSON --

type sampleBody struct {
	Name string `json:"name"`
	N    int    `json:"n"`
}

func TestDecodeJSON_HappyPath(t *testing.T) {
	body := strings.NewReader(`{"name":"alpha","n":42}`)
	req := httptest.NewRequest(http.MethodPost, "/x", body)

	var got sampleBody
	require.NoError(t, decodeJSON(req, &got))
	assert.Equal(t, "alpha", got.Name)
	assert.Equal(t, 42, got.N)
}

func TestDecodeJSON_InvalidJSONReturnsError(t *testing.T) {
	body := strings.NewReader(`{"name":"alpha", broken}`)
	req := httptest.NewRequest(http.MethodPost, "/x", body)

	var got sampleBody
	err := decodeJSON(req, &got)
	require.Error(t, err)
}

func TestDecodeJSON_EmptyBodyReturnsEOF(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/x", strings.NewReader(""))

	var got sampleBody
	err := decodeJSON(req, &got)
	assert.ErrorIs(t, err, io.EOF, "empty body should surface as io.EOF for callers to detect")
}

func TestDecodeJSON_UnknownFieldsAreIgnored(t *testing.T) {
	// Forward-compatibility: clients sending fields the server doesn't yet
	// recognise should not get a 400. encoding/json's default behavior
	// (without DisallowUnknownFields) silently drops them.
	body := strings.NewReader(`{"name":"alpha","unknown":"keep me out","n":1}`)
	req := httptest.NewRequest(http.MethodPost, "/x", body)

	var got sampleBody
	require.NoError(t, decodeJSON(req, &got))
	assert.Equal(t, "alpha", got.Name)
	assert.Equal(t, 1, got.N)
}
