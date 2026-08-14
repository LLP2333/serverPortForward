package app

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestLocalSessionAndCSRFProtection(t *testing.T) {
	manager := NewManager(newFakeWindowsRunner(), newMemoryConfigRepository())
	server, err := NewAppServer(manager)
	if err != nil {
		t.Fatal(err)
	}
	server.allowedHost = "127.0.0.1:45678"
	handler, err := server.routes()
	if err != nil {
		t.Fatal(err)
	}

	bootstrap := httptest.NewRequest(http.MethodGet, "http://127.0.0.1:45678/?token="+server.session, nil)
	bootstrap.Host = server.allowedHost
	bootstrapResponse := httptest.NewRecorder()
	handler.ServeHTTP(bootstrapResponse, bootstrap)
	if bootstrapResponse.Code != http.StatusSeeOther {
		t.Fatalf("bootstrap status = %d, want %d", bootstrapResponse.Code, http.StatusSeeOther)
	}
	cookies := bootstrapResponse.Result().Cookies()
	if len(cookies) != 1 || cookies[0].Name != "spf_session" || !cookies[0].HttpOnly {
		t.Fatalf("unexpected session cookies: %#v", cookies)
	}

	stateRequest := httptest.NewRequest(http.MethodGet, "http://127.0.0.1:45678/api/state", nil)
	stateRequest.Host = server.allowedHost
	stateRequest.AddCookie(cookies[0])
	stateResponseRecorder := httptest.NewRecorder()
	handler.ServeHTTP(stateResponseRecorder, stateRequest)
	if stateResponseRecorder.Code != http.StatusOK {
		t.Fatalf("state status = %d, body=%s", stateResponseRecorder.Code, stateResponseRecorder.Body.String())
	}
	var state stateResponse
	if err := json.Unmarshal(stateResponseRecorder.Body.Bytes(), &state); err != nil {
		t.Fatal(err)
	}
	if state.CSRFToken == "" {
		t.Fatal("state response did not include a CSRF token")
	}

	withoutCSRF := httptest.NewRequest(http.MethodPut, "http://127.0.0.1:45678/api/settings", strings.NewReader(`{"defaultTargetIPv4":"10.0.0.8"}`))
	withoutCSRF.Host = server.allowedHost
	withoutCSRF.AddCookie(cookies[0])
	withoutCSRFResponse := httptest.NewRecorder()
	handler.ServeHTTP(withoutCSRFResponse, withoutCSRF)
	if withoutCSRFResponse.Code != http.StatusForbidden {
		t.Fatalf("request without CSRF status = %d, want %d", withoutCSRFResponse.Code, http.StatusForbidden)
	}

	valid := httptest.NewRequest(http.MethodPut, "http://127.0.0.1:45678/api/settings", strings.NewReader(`{"defaultTargetIPv4":"10.0.0.8"}`))
	valid.Host = server.allowedHost
	valid.AddCookie(cookies[0])
	valid.Header.Set("Origin", "http://"+server.allowedHost)
	valid.Header.Set("X-SPF-CSRF", state.CSRFToken)
	validResponse := httptest.NewRecorder()
	handler.ServeHTTP(validResponse, valid)
	if validResponse.Code != http.StatusNoContent {
		t.Fatalf("valid settings status = %d, body=%s", validResponse.Code, validResponse.Body.String())
	}
}

func TestDecodeJSONRejectsTrailingData(t *testing.T) {
	request := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(`{"listenPort":71} trailing`))
	response := httptest.NewRecorder()
	var target map[string]any
	if decodeJSON(response, request, &target) {
		t.Fatal("expected trailing data to be rejected")
	}
	if response.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d", response.Code, http.StatusBadRequest)
	}
}

func TestWebInputsDoNotShowPlaceholderExamples(t *testing.T) {
	page, err := embeddedWeb.ReadFile("web/index.html")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(page), "placeholder=") {
		t.Fatal("input placeholder example is still present")
	}
}

func TestHiddenElementsCannotBeShownByComponentStyles(t *testing.T) {
	stylesheet, err := embeddedWeb.ReadFile("web/style.css")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(stylesheet), "[hidden] { display: none !important; }") {
		t.Fatal("hidden elements are not protected from display overrides")
	}
}
