// realm-panel: a small, dependency-free control plane for Realm agents.
//
// Required environment variables:
//
//	PANEL_PASSWORD  password used by the web login page
//	REALM_TOKEN     shared secret used by the panel and every agent
//
// Optional environment variables:
//
//	PANEL_ADDR      listen address (default :6800)
//	DATA_DIR        directory for nodes.json/rules.json (default .)
//	AGENT_BINARY    prebuilt Linux agent served to installers
//	                (default ./agent-linux-amd64)
package main

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

const tokenHeader = "X-Realm-Token"

type Node struct {
	ID       string    `json:"id"`
	Name     string    `json:"name"`
	IP       string    `json:"ip"`
	AgentURL string    `json:"agent_url"`
	LastSeen time.Time `json:"last_seen"`
}

type Rule struct {
	ID        string    `json:"id"`
	NodeID    string    `json:"node_id"`
	Listen    string    `json:"listen"`
	Remote    string    `json:"remote"`
	CreatedAt time.Time `json:"created_at"`
}

type Store struct {
	mu      sync.RWMutex
	nodes   map[string]Node
	rules   map[string]Rule
	dataDir string
}

func newStore(dir string) (*Store, error) {
	s := &Store{nodes: map[string]Node{}, rules: map[string]Rule{}, dataDir: dir}
	if err := os.MkdirAll(dir, 0700); err != nil {
		return nil, err
	}
	if err := loadJSON(filepath.Join(dir, "nodes.json"), &s.nodes); err != nil {
		return nil, err
	}
	if err := loadJSON(filepath.Join(dir, "rules.json"), &s.rules); err != nil {
		return nil, err
	}
	return s, nil
}

func loadJSON(path string, dst any) error {
	b, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	if len(bytes.TrimSpace(b)) == 0 {
		return nil
	}
	return json.Unmarshal(b, dst)
}

func writeJSONAtomic(path string, v any) error {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	b = append(b, '\n')
	tmp, err := os.CreateTemp(filepath.Dir(path), ".realm-panel-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)
	if err = tmp.Chmod(0600); err == nil {
		_, err = tmp.Write(b)
	}
	if closeErr := tmp.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		return err
	}
	return os.Rename(tmpName, path)
}

func (s *Store) saveNodesLocked() error {
	return writeJSONAtomic(filepath.Join(s.dataDir, "nodes.json"), s.nodes)
}
func (s *Store) saveRulesLocked() error {
	return writeJSONAtomic(filepath.Join(s.dataDir, "rules.json"), s.rules)
}

type App struct {
	store         *Store
	password      string
	token         string
	sessionKey    []byte
	agentBinary   string
	binaryMAC     string
	client        *http.Client
	tmpl          *template.Template
	replay        *ReplayGuard
	loginLimit    *RateLimiter
	apiLimit      *RateLimiter
	downloadLimit *RateLimiter
}

type ReplayGuard struct {
	mu   sync.Mutex
	seen map[string]time.Time
}

type rateEntry struct {
	window time.Time
	count  int
}

type RateLimiter struct {
	mu      sync.Mutex
	entries map[string]rateEntry
	limit   int
	window  time.Duration
}

func main() {
	password := os.Getenv("PANEL_PASSWORD")
	token := os.Getenv("REALM_TOKEN")
	if len(password) < 12 || len(token) < 32 {
		log.Fatal("PANEL_PASSWORD must be at least 12 characters and REALM_TOKEN at least 32 characters")
	}
	dataDir := getenv("DATA_DIR", ".")
	store, err := newStore(dataDir)
	if err != nil {
		log.Fatal(err)
	}
	h := sha256.Sum256([]byte("realm-panel-session\x00" + password + "\x00" + token))
	agentBinary := getenv("AGENT_BINARY", "./agent-linux-amd64")
	binaryMAC, err := fileHMAC(agentBinary, token)
	if err != nil {
		log.Fatalf("cannot authenticate agent binary: %v", err)
	}
	app := &App{
		store: store, password: password, token: token, sessionKey: h[:],
		agentBinary:   agentBinary,
		binaryMAC:     binaryMAC,
		client:        &http.Client{Timeout: 12 * time.Second},
		replay:        &ReplayGuard{seen: make(map[string]time.Time)},
		loginLimit:    &RateLimiter{entries: make(map[string]rateEntry), limit: 10, window: 5 * time.Minute},
		apiLimit:      &RateLimiter{entries: make(map[string]rateEntry), limit: 120, window: time.Minute},
		downloadLimit: &RateLimiter{entries: make(map[string]rateEntry), limit: 20, window: time.Minute},
		tmpl: template.Must(template.New("panel").Funcs(template.FuncMap{
			"age": func(t time.Time) string {
				if t.IsZero() {
					return "从未"
				}
				return time.Since(t).Round(time.Second).String()
			},
			"nodeName": func(nodes map[string]Node, id string) string {
				if n, ok := nodes[id]; ok {
					return n.Name
				}
				return id
			},
		}).Parse(pageHTML)),
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/", app.handleHome)
	mux.HandleFunc("/login", app.rateLimited(app.loginLimit, app.handleLogin))
	mux.HandleFunc("/logout", app.handleLogout)
	mux.HandleFunc("/api/register", app.rateLimited(app.apiLimit, app.handleRegister))
	mux.HandleFunc("/api/add_rule", app.handleAddRule)
	mux.HandleFunc("/api/delete_rule", app.handleDeleteRule)
	mux.HandleFunc("/downloads/agent-linux-amd64", app.rateLimited(app.downloadLimit, app.handleAgentDownload))
	addr := getenv("PANEL_ADDR", ":6800")
	server := &http.Server{Addr: addr, Handler: securityHeaders(mux), ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 15 * time.Second, WriteTimeout: 30 * time.Second, IdleTimeout: 60 * time.Second, MaxHeaderBytes: 16 << 10}
	log.Printf("realm panel listening on %s", addr)
	log.Fatal(server.ListenAndServe())
}

func getenv(k, fallback string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return fallback
}

func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("Content-Security-Policy", "default-src 'self'; style-src 'unsafe-inline'")
		next.ServeHTTP(w, r)
	})
}

func (l *RateLimiter) allow(key string) bool {
	now := time.Now()
	l.mu.Lock()
	defer l.mu.Unlock()
	e := l.entries[key]
	if e.window.IsZero() || now.Sub(e.window) >= l.window {
		e = rateEntry{window: now}
	}
	e.count++
	l.entries[key] = e
	if len(l.entries) > 4096 {
		for k, v := range l.entries {
			if now.Sub(v.window) >= l.window {
				delete(l.entries, k)
			}
		}
	}
	return e.count <= l.limit
}

func remoteIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err == nil {
		return host
	}
	return r.RemoteAddr
}

func (a *App) rateLimited(l *RateLimiter, next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !l.allow(remoteIP(r)) {
			w.Header().Set("Retry-After", "60")
			jsonError(w, "too many requests", http.StatusTooManyRequests)
			return
		}
		next(w, r)
	}
}

// verifySignedRequest checks a time-bound HMAC signature and consumes its nonce.
// The shared token is never sent over the network.
func (a *App) verifySignedRequest(r *http.Request) bool {
	body, err := io.ReadAll(io.LimitReader(r.Body, (64<<10)+1))
	if err != nil || len(body) > 64<<10 {
		return false
	}
	r.Body = io.NopCloser(bytes.NewReader(body))
	ts := r.Header.Get("X-Realm-Timestamp")
	nonce := r.Header.Get("X-Realm-Nonce")
	sig, err := hex.DecodeString(r.Header.Get(tokenHeader))
	if err != nil || len(nonce) < 20 || len(nonce) > 64 {
		return false
	}
	unix, err := strconv.ParseInt(ts, 10, 64)
	if err != nil || absDuration(time.Since(time.Unix(unix, 0))) > 5*time.Minute {
		return false
	}
	bodyHash := sha256.Sum256(body)
	message := r.Method + "\n" + r.URL.Path + "\n" + ts + "\n" + nonce + "\n" + hex.EncodeToString(bodyHash[:])
	mac := hmac.New(sha256.New, []byte(a.token))
	_, _ = mac.Write([]byte(message))
	if !hmac.Equal(sig, mac.Sum(nil)) {
		return false
	}
	return a.replay.consume(nonce, time.Now().Add(6*time.Minute))
}

func (g *ReplayGuard) consume(nonce string, expiry time.Time) bool {
	now := time.Now()
	g.mu.Lock()
	defer g.mu.Unlock()
	for k, exp := range g.seen {
		if now.After(exp) {
			delete(g.seen, k)
		}
	}
	if _, exists := g.seen[nonce]; exists {
		return false
	}
	g.seen[nonce] = expiry
	return true
}

func absDuration(d time.Duration) time.Duration {
	if d < 0 {
		return -d
	}
	return d
}

func (a *App) issueSession(w http.ResponseWriter, r *http.Request) {
	exp := time.Now().Add(12 * time.Hour).Unix()
	payload := strconv.FormatInt(exp, 10)
	mac := hmac.New(sha256.New, a.sessionKey)
	_, _ = mac.Write([]byte(payload))
	value := base64.RawURLEncoding.EncodeToString([]byte(payload + "." + hex.EncodeToString(mac.Sum(nil))))
	secure := r.TLS != nil || strings.EqualFold(r.Header.Get("X-Forwarded-Proto"), "https")
	http.SetCookie(w, &http.Cookie{Name: "realm_session", Value: value, Path: "/", HttpOnly: true, Secure: secure, SameSite: http.SameSiteStrictMode, MaxAge: 43200})
}

func (a *App) validSession(r *http.Request) bool {
	c, err := r.Cookie("realm_session")
	if err != nil {
		return false
	}
	b, err := base64.RawURLEncoding.DecodeString(c.Value)
	if err != nil {
		return false
	}
	parts := strings.Split(string(b), ".")
	if len(parts) != 2 {
		return false
	}
	exp, err := strconv.ParseInt(parts[0], 10, 64)
	if err != nil || time.Now().Unix() > exp {
		return false
	}
	want, err := hex.DecodeString(parts[1])
	if err != nil {
		return false
	}
	mac := hmac.New(sha256.New, a.sessionKey)
	_, _ = mac.Write([]byte(parts[0]))
	return hmac.Equal(want, mac.Sum(nil))
}

func (a *App) requireUser(w http.ResponseWriter, r *http.Request) bool {
	if a.validSession(r) {
		if r.Method != http.MethodGet && r.Method != http.MethodHead && !sameOrigin(r) {
			jsonError(w, "cross-site request rejected", http.StatusForbidden)
			return false
		}
		return true
	}
	if strings.HasPrefix(r.URL.Path, "/api/") {
		jsonError(w, "unauthorized", http.StatusUnauthorized)
	} else {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
	}
	return false
}

func sameOrigin(r *http.Request) bool {
	if site := r.Header.Get("Sec-Fetch-Site"); site != "" && site != "same-origin" && site != "none" {
		return false
	}
	origin := r.Header.Get("Origin")
	if origin == "" {
		return true
	}
	u, err := url.Parse(origin)
	return err == nil && strings.EqualFold(u.Host, r.Host)
}

func (a *App) handleLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		_, _ = io.WriteString(w, loginHTML)
		return
	}
	if r.Method != http.MethodPost {
		methodNotAllowed(w)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 4<<10)
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad form", 400)
		return
	}
	if subtle.ConstantTimeCompare([]byte(r.FormValue("password")), []byte(a.password)) != 1 {
		http.Error(w, "密码错误", http.StatusUnauthorized)
		return
	}
	a.issueSession(w, r)
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func (a *App) handleLogout(w http.ResponseWriter, r *http.Request) {
	http.SetCookie(w, &http.Cookie{Name: "realm_session", Value: "", Path: "/", HttpOnly: true, MaxAge: -1, SameSite: http.SameSiteStrictMode})
	http.Redirect(w, r, "/login", http.StatusSeeOther)
}

func (a *App) handleHome(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	if !a.requireUser(w, r) {
		return
	}
	a.store.mu.RLock()
	nodes := make(map[string]Node, len(a.store.nodes))
	for k, v := range a.store.nodes {
		nodes[k] = v
	}
	rules := make([]Rule, 0, len(a.store.rules))
	for _, v := range a.store.rules {
		rules = append(rules, v)
	}
	a.store.mu.RUnlock()
	sort.Slice(rules, func(i, j int) bool { return rules[i].CreatedAt.After(rules[j].CreatedAt) })
	msg := r.URL.Query().Get("msg")
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := a.tmpl.Execute(w, map[string]any{"Nodes": nodes, "Rules": rules, "Message": msg}); err != nil {
		log.Printf("template: %v", err)
	}
}

type registerRequest struct {
	Name     string `json:"name"`
	IP       string `json:"ip"`
	AgentURL string `json:"agent_url"`
}

func (a *App) handleRegister(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		methodNotAllowed(w)
		return
	}
	if !a.verifySignedRequest(r) {
		jsonError(w, "invalid or replayed signature", 401)
		return
	}
	var req registerRequest
	if err := decodeJSON(r, &req); err != nil {
		jsonError(w, err.Error(), 400)
		return
	}
	req.Name = strings.TrimSpace(req.Name)
	req.IP = strings.TrimSpace(req.IP)
	req.AgentURL = strings.TrimRight(strings.TrimSpace(req.AgentURL), "/")
	if req.Name == "" || len(req.Name) > 80 {
		jsonError(w, "invalid node name", 400)
		return
	}
	if req.IP == "" {
		req.IP, _, _ = net.SplitHostPort(r.RemoteAddr)
	}
	u, err := url.Parse(req.AgentURL)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" || u.User != nil {
		jsonError(w, "invalid agent_url", 400)
		return
	}
	idHash := sha256.Sum256([]byte(req.Name + "\x00" + req.AgentURL))
	id := hex.EncodeToString(idHash[:8])
	n := Node{ID: id, Name: req.Name, IP: req.IP, AgentURL: req.AgentURL, LastSeen: time.Now().UTC()}
	a.store.mu.Lock()
	previous, existed := a.store.nodes[id]
	a.store.nodes[id] = n
	metadataChanged := !existed || previous.Name != n.Name || previous.IP != n.IP || previous.AgentURL != n.AgentURL
	if metadataChanged || time.Since(previous.LastSeen) >= 5*time.Minute {
		err = a.store.saveNodesLocked()
	}
	a.store.mu.Unlock()
	if err != nil {
		jsonError(w, "cannot save node", 500)
		return
	}
	writeJSON(w, 200, map[string]any{"ok": true, "node_id": id})
}

func (a *App) handleAddRule(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		methodNotAllowed(w)
		return
	}
	if !a.requireUser(w, r) {
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 16<<10)
	var nodeID, listen, remote string
	if strings.Contains(r.Header.Get("Content-Type"), "application/json") {
		var req struct {
			NodeID string `json:"node_id"`
			Listen string `json:"listen"`
			Remote string `json:"remote"`
		}
		if err := decodeJSON(r, &req); err != nil {
			jsonError(w, err.Error(), 400)
			return
		}
		nodeID, listen, remote = req.NodeID, req.Listen, req.Remote
	} else {
		_ = r.ParseForm()
		nodeID, listen, remote = r.FormValue("node_id"), r.FormValue("listen"), r.FormValue("remote")
	}
	listen, remote = strings.TrimSpace(listen), strings.TrimSpace(remote)
	if err := validateEndpoint(listen, true); err != nil {
		a.actionError(w, r, "监听地址: "+err.Error(), 400)
		return
	}
	if err := validateEndpoint(remote, false); err != nil {
		a.actionError(w, r, "目标地址: "+err.Error(), 400)
		return
	}
	a.store.mu.RLock()
	node, ok := a.store.nodes[nodeID]
	a.store.mu.RUnlock()
	if !ok {
		a.actionError(w, r, "节点不存在", 404)
		return
	}
	id, err := randomID()
	if err != nil {
		a.actionError(w, r, "生成规则 ID 失败", 500)
		return
	}
	rule := Rule{ID: id, NodeID: nodeID, Listen: listen, Remote: remote, CreatedAt: time.Now().UTC()}
	if err := a.callAgent(r.Context(), node, "/api/rules/add", rule); err != nil {
		a.actionError(w, r, "Agent 执行失败: "+err.Error(), 502)
		return
	}
	a.store.mu.Lock()
	a.store.rules[id] = rule
	err = a.store.saveRulesLocked()
	a.store.mu.Unlock()
	if err != nil {
		_ = a.callAgent(context.Background(), node, "/api/rules/delete", map[string]string{"id": id})
		a.actionError(w, r, "面板保存失败，已尝试回滚 Agent", 500)
		return
	}
	a.actionOK(w, r, "规则添加成功")
}

func (a *App) handleDeleteRule(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		methodNotAllowed(w)
		return
	}
	if !a.requireUser(w, r) {
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 16<<10)
	var id string
	if strings.Contains(r.Header.Get("Content-Type"), "application/json") {
		var req struct{ ID string }
		if err := decodeJSON(r, &req); err != nil {
			jsonError(w, err.Error(), 400)
			return
		}
		id = req.ID
	} else {
		_ = r.ParseForm()
		id = r.FormValue("id")
	}
	a.store.mu.RLock()
	rule, ok := a.store.rules[id]
	node := a.store.nodes[rule.NodeID]
	a.store.mu.RUnlock()
	if !ok {
		a.actionError(w, r, "规则不存在", 404)
		return
	}
	if err := a.callAgent(r.Context(), node, "/api/rules/delete", map[string]string{"id": id}); err != nil {
		a.actionError(w, r, "Agent 执行失败: "+err.Error(), 502)
		return
	}
	a.store.mu.Lock()
	delete(a.store.rules, id)
	err := a.store.saveRulesLocked()
	a.store.mu.Unlock()
	if err != nil {
		a.actionError(w, r, "Agent 已删除规则，但面板持久化失败", 500)
		return
	}
	a.actionOK(w, r, "规则删除成功")
}

func (a *App) callAgent(ctx context.Context, node Node, path string, payload any) error {
	b, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	b, err = encryptPayload(a.token, b)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, node.AgentURL+path, bytes.NewReader(b))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/vnd.realm.encrypted+json")
	if err := signRequest(req, b, a.token); err != nil {
		return err
	}
	resp, err := a.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	result, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	if resp.StatusCode/100 != 2 {
		return fmt.Errorf("HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(result)))
	}
	return nil
}

func signRequest(req *http.Request, body []byte, token string) error {
	nonceBytes := make([]byte, 18)
	if _, err := rand.Read(nonceBytes); err != nil {
		return err
	}
	nonce := base64.RawURLEncoding.EncodeToString(nonceBytes)
	ts := strconv.FormatInt(time.Now().Unix(), 10)
	bodyHash := sha256.Sum256(body)
	message := req.Method + "\n" + req.URL.Path + "\n" + ts + "\n" + nonce + "\n" + hex.EncodeToString(bodyHash[:])
	mac := hmac.New(sha256.New, []byte(token))
	_, _ = mac.Write([]byte(message))
	req.Header.Set("X-Realm-Timestamp", ts)
	req.Header.Set("X-Realm-Nonce", nonce)
	req.Header.Set(tokenHeader, hex.EncodeToString(mac.Sum(nil)))
	return nil
}

// encryptPayload protects panel-to-agent commands with AES-256-GCM. HTTPS is
// still required in production because the authentication header is sensitive.
func encryptPayload(token string, plaintext []byte) ([]byte, error) {
	key := sha256.Sum256([]byte("realm-command-v1\x00" + token))
	block, err := aes.NewCipher(key[:])
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	ciphertext := gcm.Seal(nil, nonce, plaintext, []byte("realm-command-v1"))
	return json.Marshal(map[string]string{
		"nonce":      base64.RawStdEncoding.EncodeToString(nonce),
		"ciphertext": base64.RawStdEncoding.EncodeToString(ciphertext),
	})
}

func (a *App) handleAgentDownload(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		methodNotAllowed(w)
		return
	}
	w.Header().Set("Content-Disposition", `attachment; filename="realm-agent"`)
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("X-Realm-Binary-HMAC", a.binaryMAC)
	http.ServeFile(w, r, a.agentBinary)
}

func fileHMAC(path, token string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	mac := hmac.New(sha256.New, []byte(token))
	if _, err := io.Copy(mac, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(mac.Sum(nil)), nil
}

func validateEndpoint(s string, listen bool) error {
	if len(s) < 2 || len(s) > 255 || strings.ContainsAny(s, "\r\n\t\"") {
		return errors.New("格式无效")
	}
	host, port, err := net.SplitHostPort(s)
	if err != nil {
		return errors.New("请使用 host:port（IPv6 要写成 [addr]:port）")
	}
	p, err := strconv.Atoi(port)
	if err != nil || p < 1 || p > 65535 {
		return errors.New("端口范围必须是 1-65535")
	}
	if !listen && strings.TrimSpace(host) == "" {
		return errors.New("目标主机不能为空")
	}
	return nil
}

func randomID() (string, error) {
	b := make([]byte, 12)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}
func decodeJSON(r *http.Request, dst any) error {
	defer r.Body.Close()
	d := json.NewDecoder(io.LimitReader(r.Body, 64<<10))
	d.DisallowUnknownFields()
	return d.Decode(dst)
}
func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
func jsonError(w http.ResponseWriter, msg string, status int) {
	writeJSON(w, status, map[string]any{"ok": false, "error": msg})
}
func methodNotAllowed(w http.ResponseWriter) {
	jsonError(w, "method not allowed", http.StatusMethodNotAllowed)
}
func wantsJSON(r *http.Request) bool {
	return strings.Contains(r.Header.Get("Accept"), "application/json") || strings.Contains(r.Header.Get("Content-Type"), "application/json")
}
func (a *App) actionError(w http.ResponseWriter, r *http.Request, msg string, status int) {
	if wantsJSON(r) {
		jsonError(w, msg, status)
	} else {
		http.Redirect(w, r, "/?msg="+url.QueryEscape(msg), http.StatusSeeOther)
	}
}
func (a *App) actionOK(w http.ResponseWriter, r *http.Request, msg string) {
	if wantsJSON(r) {
		writeJSON(w, 200, map[string]any{"ok": true})
	} else {
		http.Redirect(w, r, "/?msg="+url.QueryEscape(msg), http.StatusSeeOther)
	}
}

const loginHTML = `<!doctype html><html lang="zh-CN"><meta charset="utf-8"><meta name="viewport" content="width=device-width"><title>Realm 登录</title><style>body{font:16px system-ui;background:#101827;color:#e5e7eb;display:grid;place-items:center;height:100vh;margin:0}form{background:#1f2937;padding:28px;border-radius:14px;width:min(340px,80vw)}input,button{box-sizing:border-box;width:100%;padding:12px;margin-top:12px;border-radius:8px;border:1px solid #4b5563}button{background:#2563eb;color:white;border:0}</style><form method="post"><h2>Realm 管理面板</h2><input name="password" type="password" placeholder="管理密码" required autofocus><button>登录</button></form></html>`

const pageHTML = `<!doctype html><html lang="zh-CN"><meta charset="utf-8"><meta name="viewport" content="width=device-width"><title>Realm 面板</title><style>body{font:15px system-ui;background:#f3f4f6;color:#111827;margin:0}.wrap{max-width:1050px;margin:auto;padding:24px}.top{display:flex;justify-content:space-between;align-items:center}.card{background:white;padding:20px;margin:18px 0;border-radius:12px;box-shadow:0 2px 10px #0001}input,select,button{padding:9px;border:1px solid #d1d5db;border-radius:7px}button{background:#2563eb;color:white;border:0}.danger{background:#dc2626}table{width:100%;border-collapse:collapse}th,td{text-align:left;border-bottom:1px solid #e5e7eb;padding:10px}.msg{background:#dbeafe;padding:10px;border-radius:8px}.muted{color:#6b7280;font-size:13px}@media(max-width:700px){table{display:block;overflow:auto}}</style><div class="wrap"><div class="top"><h1>Realm 转发管理</h1><a href="/logout">退出</a></div>{{if .Message}}<div class="msg">{{.Message}}</div>{{end}}<div class="card"><h2>添加规则</h2><form method="post" action="/api/add_rule"><select name="node_id" required><option value="">选择节点</option>{{range $id,$n := .Nodes}}<option value="{{$id}}">{{$n.Name}}（{{$n.IP}}）</option>{{end}}</select> <input name="listen" placeholder="0.0.0.0:5000" required> <input name="remote" placeholder="目标IP或域名:端口" required> <button>保存并应用</button></form></div><div class="card"><h2>节点</h2><table><tr><th>名称</th><th>IP</th><th>Agent</th><th>最后注册/心跳</th></tr>{{range $id,$n := .Nodes}}<tr><td>{{$n.Name}}</td><td>{{$n.IP}}</td><td>{{$n.AgentURL}}</td><td>{{age $n.LastSeen}} 前</td></tr>{{else}}<tr><td colspan="4" class="muted">暂无节点，请在节点机器执行安装命令。</td></tr>{{end}}</table></div><div class="card"><h2>转发规则</h2><table><tr><th>节点</th><th>监听</th><th>目标</th><th></th></tr>{{range .Rules}}<tr><td>{{nodeName $.Nodes .NodeID}}</td><td>{{.Listen}}</td><td>{{.Remote}}</td><td><form method="post" action="/api/delete_rule"><input type="hidden" name="id" value="{{.ID}}"><button class="danger">删除</button></form></td></tr>{{else}}<tr><td colspan="4" class="muted">暂无规则。</td></tr>{{end}}</table></div></div></html>`
