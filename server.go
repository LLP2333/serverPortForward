package main

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"embed"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log"
	"net"
	"net/http"
	"net/url"
	"sync"
	"time"
)

//go:embed web/*
var embeddedWeb embed.FS

type AppServer struct {
	manager *Manager
	session string
	csrf    string

	mu          sync.RWMutex
	allowedHost string
	shutdown    chan struct{}
	shutdownOne sync.Once
}

type stateResponse struct {
	AppState
	CSRFToken string `json:"csrfToken"`
}

func NewAppServer(manager *Manager) (*AppServer, error) {
	session, err := randomToken(32)
	if err != nil {
		return nil, err
	}
	csrf, err := randomToken(32)
	if err != nil {
		return nil, err
	}
	return &AppServer{manager: manager, session: session, csrf: csrf, shutdown: make(chan struct{})}, nil
}

func (s *AppServer) Run(ctx context.Context) error {
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		return fmt.Errorf("监听本地管理端口: %w", err)
	}
	s.mu.Lock()
	s.allowedHost = listener.Addr().String()
	host := s.allowedHost
	s.mu.Unlock()

	mux, err := s.routes()
	if err != nil {
		listener.Close()
		return err
	}
	httpServer := &http.Server{
		Handler:           s.securityHeaders(mux),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      90 * time.Second,
		IdleTimeout:       60 * time.Second,
	}
	serveResult := make(chan error, 1)
	go func() {
		err := httpServer.Serve(listener)
		if errors.Is(err, http.ErrServerClosed) {
			err = nil
		}
		serveResult <- err
	}()

	bootstrapURL := "http://" + host + "/?token=" + url.QueryEscape(s.session)
	if err := platformOpenBrowser(bootstrapURL); err != nil {
		_ = httpServer.Shutdown(context.Background())
		return fmt.Errorf("打开浏览器: %w", err)
	}
	log.Printf("本地管理界面已启动: http://%s", host)

	select {
	case <-ctx.Done():
	case <-s.shutdown:
	case err := <-serveResult:
		return err
	}
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	return httpServer.Shutdown(shutdownCtx)
}

func (s *AppServer) routes() (http.Handler, error) {
	webRoot, err := fs.Sub(embeddedWeb, "web")
	if err != nil {
		return nil, err
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/api/state", s.api(s.handleState))
	mux.HandleFunc("/api/settings", s.api(s.handleSettings))
	mux.HandleFunc("/api/rules/test", s.api(s.handleRuleTest))
	mux.HandleFunc("/api/rules", s.api(s.handleRules))
	mux.HandleFunc("/api/managed-rules/clear", s.api(s.handleClearManaged))
	mux.HandleFunc("/api/iphelper/start", s.api(s.handleStartIPHelper))
	mux.HandleFunc("/api/app/exit", s.api(s.handleExit))
	mux.Handle("/", s.web(http.FileServer(http.FS(webRoot))))
	return mux, nil
}

func (s *AppServer) handleState(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeMethodNotAllowed(w, http.MethodGet)
		return
	}
	state, err := s.manager.State(r.Context())
	if err != nil {
		writeAPIError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, stateResponse{AppState: state, CSRFToken: s.csrf})
}

func (s *AppServer) handleSettings(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPut {
		writeMethodNotAllowed(w, http.MethodPut)
		return
	}
	var req SettingsRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	if err := s.manager.UpdateSettings(r.Context(), req); err != nil {
		writeAPIError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *AppServer) handleRules(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodPost:
		var req RuleInput
		if !decodeJSON(w, r, &req) {
			return
		}
		if err := s.manager.CreateRule(r.Context(), req); err != nil {
			writeAPIError(w, err)
			return
		}
	case http.MethodPut:
		var req UpdateRuleRequest
		if !decodeJSON(w, r, &req) {
			return
		}
		if err := s.manager.UpdateRule(r.Context(), req); err != nil {
			writeAPIError(w, err)
			return
		}
	case http.MethodDelete:
		var req RuleKeyRequest
		if !decodeJSON(w, r, &req) {
			return
		}
		if err := s.manager.DeleteRule(r.Context(), req); err != nil {
			writeAPIError(w, err)
			return
		}
	default:
		writeMethodNotAllowed(w, http.MethodPost+", "+http.MethodPut+", "+http.MethodDelete)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *AppServer) handleRuleTest(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeMethodNotAllowed(w, http.MethodPost)
		return
	}
	var req RuleKeyRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	result, err := s.manager.TestRule(r.Context(), req)
	if err != nil {
		writeAPIError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, result)
}

func (s *AppServer) handleClearManaged(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeMethodNotAllowed(w, http.MethodPost)
		return
	}
	if err := s.manager.ClearManagedRules(r.Context()); err != nil {
		writeAPIError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *AppServer) handleStartIPHelper(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeMethodNotAllowed(w, http.MethodPost)
		return
	}
	if err := s.manager.StartIPHelper(r.Context()); err != nil {
		writeAPIError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *AppServer) handleExit(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeMethodNotAllowed(w, http.MethodPost)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"message": "管理器已退出，Windows 转发规则继续有效。"})
	go func() {
		time.Sleep(150 * time.Millisecond)
		s.shutdownOne.Do(func() { close(s.shutdown) })
	}()
}

func (s *AppServer) api(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !s.validHost(r.Host) || !s.validSession(r) {
			writeAPIError(w, appError("UNAUTHORIZED", "无权访问本地管理接口", "会话无效，请重新启动程序。", http.StatusUnauthorized))
			return
		}
		w.Header().Set("Cache-Control", "no-store")
		if r.Method != http.MethodGet {
			expectedOrigin := "http://" + r.Host
			if r.Header.Get("Origin") != expectedOrigin || subtle.ConstantTimeCompare([]byte(r.Header.Get("X-SPF-CSRF")), []byte(s.csrf)) != 1 {
				writeAPIError(w, appError("CSRF_REJECTED", "请求来源校验失败", "请刷新管理页面后重试。", http.StatusForbidden))
				return
			}
		}
		next(w, r)
	}
}

func (s *AppServer) web(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !s.validHost(r.Host) {
			http.Error(w, "invalid host", http.StatusBadRequest)
			return
		}
		if token := r.URL.Query().Get("token"); token != "" {
			if subtle.ConstantTimeCompare([]byte(token), []byte(s.session)) != 1 {
				http.Error(w, "invalid session", http.StatusUnauthorized)
				return
			}
			http.SetCookie(w, &http.Cookie{
				Name: "spf_session", Value: s.session, Path: "/", HttpOnly: true,
				SameSite: http.SameSiteStrictMode, Secure: false,
			})
			http.Redirect(w, r, "/", http.StatusSeeOther)
			return
		}
		if !s.validSession(r) {
			http.Error(w, "会话已失效，请重新启动 ServerPortForward。", http.StatusUnauthorized)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func (s *AppServer) validHost(host string) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return host == s.allowedHost
}

func (s *AppServer) validSession(r *http.Request) bool {
	cookie, err := r.Cookie("spf_session")
	if err != nil {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(cookie.Value), []byte(s.session)) == 1
}

func (s *AppServer) securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Security-Policy", "default-src 'self'; img-src 'self' data:; style-src 'self'; script-src 'self'; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Referrer-Policy", "no-referrer")
		next.ServeHTTP(w, r)
	})
}

func decodeJSON(w http.ResponseWriter, r *http.Request, target any) bool {
	r.Body = http.MaxBytesReader(w, r.Body, 64<<10)
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		writeAPIError(w, appError("INVALID_JSON", "请求数据格式错误", err.Error(), http.StatusBadRequest))
		return false
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		writeAPIError(w, appError("INVALID_JSON", "请求数据格式错误", "只能包含一个 JSON 对象", http.StatusBadRequest))
		return false
	}
	return true
}

func writeAPIError(w http.ResponseWriter, err error) {
	appErr := asAppError(err)
	writeJSON(w, appErr.HTTPStatus, appErr)
}

func writeMethodNotAllowed(w http.ResponseWriter, allow string) {
	w.Header().Set("Allow", allow)
	writeAPIError(w, appError("METHOD_NOT_ALLOWED", "不支持的请求方法", "允许的方法："+allow, http.StatusMethodNotAllowed))
}

func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}

func randomToken(bytes int) (string, error) {
	value := make([]byte, bytes)
	if _, err := rand.Read(value); err != nil {
		return "", fmt.Errorf("生成安全令牌: %w", err)
	}
	return hex.EncodeToString(value), nil
}
