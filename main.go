// realm-panel: a small, dependency-free control plane for Realm agents.
//
// Required environment variables:
//
//	PANEL_USERNAME  username used by the web login page
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
	username      string
	password      string
	token         string
	sessionKey    []byte
	agentBinary   string
	binaryMAC     string
	client        *http.Client
	tmpl          *template.Template
	bindTmpl      *template.Template
	loginTmpl     *template.Template
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
	username := strings.TrimSpace(os.Getenv("PANEL_USERNAME"))
	password := os.Getenv("PANEL_PASSWORD")
	token := os.Getenv("REALM_TOKEN")
	if len(username) < 3 || len(username) > 64 || len(password) < 12 || len(token) < 32 {
		log.Fatal("PANEL_USERNAME must be 3-64 characters, PANEL_PASSWORD at least 12 characters, and REALM_TOKEN at least 32 characters")
	}
	dataDir := getenv("DATA_DIR", ".")
	store, err := newStore(dataDir)
	if err != nil {
		log.Fatal(err)
	}
	h := sha256.Sum256([]byte("realm-panel-session\x00" + username + "\x00" + password + "\x00" + token))
	agentBinary := getenv("AGENT_BINARY", "./agent-linux-amd64")
	binaryMAC, err := fileHMAC(agentBinary, token)
	if err != nil {
		log.Fatalf("cannot authenticate agent binary: %v", err)
	}
	app := &App{
		store: store, username: username, password: password, token: token, sessionKey: h[:],
		agentBinary:   agentBinary,
		binaryMAC:     binaryMAC,
		client:        &http.Client{Timeout: 12 * time.Second},
		replay:        &ReplayGuard{seen: make(map[string]time.Time)},
		loginLimit:    &RateLimiter{entries: make(map[string]rateEntry), limit: 10, window: 5 * time.Minute},
		apiLimit:      &RateLimiter{entries: make(map[string]rateEntry), limit: 120, window: time.Minute},
		downloadLimit: &RateLimiter{entries: make(map[string]rateEntry), limit: 20, window: time.Minute},
		tmpl: template.Must(template.New("panel").Funcs(template.FuncMap{
			"age":    relativeTime,
			"online": func(t time.Time) bool { return !t.IsZero() && time.Since(t) < 150*time.Second },
			"nodeName": func(nodes map[string]Node, id string) string {
				if n, ok := nodes[id]; ok {
					return n.Name
				}
				return id
			},
		}).Parse(pageHTML)),
		bindTmpl:  template.Must(template.New("bind").Parse(bindPageHTML)),
		loginTmpl: template.Must(template.New("login").Parse(loginHTML)),
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/", app.handleHome)
	mux.HandleFunc("/login", app.rateLimited(app.loginLimit, app.handleLogin))
	mux.HandleFunc("/logout", app.handleLogout)
	mux.HandleFunc("/bind", app.handleBind)
	mux.HandleFunc("/static/app.css", handleAppCSS)
	mux.HandleFunc("/static/app.js", handleAppJS)
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
		w.Header().Set("Content-Security-Policy", "default-src 'self'; style-src 'self'; script-src 'self'; img-src 'self'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'")
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
	w.Header().Set("Cache-Control", "no-store, max-age=0")
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if r.Method == http.MethodGet {
		_ = a.loginTmpl.Execute(w, nil)
		return
	}
	if r.Method != http.MethodPost {
		methodNotAllowed(w)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 4<<10)
	if err := r.ParseForm(); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		_ = a.loginTmpl.Execute(w, map[string]string{"Error": "提交内容无效，请重新输入。"})
		return
	}
	userOK := subtle.ConstantTimeCompare([]byte(r.FormValue("username")), []byte(a.username))
	passwordOK := subtle.ConstantTimeCompare([]byte(r.FormValue("password")), []byte(a.password))
	if userOK&passwordOK != 1 {
		w.WriteHeader(http.StatusUnauthorized)
		_ = a.loginTmpl.Execute(w, map[string]string{"Error": "用户名或密码错误，请检查后重试。"})
		return
	}
	a.issueSession(w, r)
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func (a *App) handleLogout(w http.ResponseWriter, r *http.Request) {
	http.SetCookie(w, &http.Cookie{Name: "realm_session", Value: "", Path: "/", HttpOnly: true, MaxAge: -1, SameSite: http.SameSiteStrictMode})
	http.Redirect(w, r, "/login", http.StatusSeeOther)
}

type bindPageData struct {
	MasterURL string
	NodeName  string
	Command   string
	Error     string
}

func (a *App) handleBind(w http.ResponseWriter, r *http.Request) {
	if !a.requireUser(w, r) {
		return
	}
	w.Header().Set("Cache-Control", "no-store, max-age=0")
	w.Header().Set("Pragma", "no-cache")
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	data := bindPageData{MasterURL: requestBaseURL(r)}
	if r.Method == http.MethodPost {
		r.Body = http.MaxBytesReader(w, r.Body, 8<<10)
		if err := r.ParseForm(); err != nil {
			data.Error = "提交内容无效"
		} else {
			data.MasterURL = strings.TrimRight(strings.TrimSpace(r.FormValue("master_url")), "/")
			data.NodeName = strings.TrimSpace(r.FormValue("node_name"))
			u, err := url.Parse(data.MasterURL)
			if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
				data.Error = "主控地址必须是完整的 http:// 或 https:// 地址"
			} else if data.NodeName == "" || len(data.NodeName) > 80 || strings.ContainsAny(data.NodeName, "\r\n\x00") {
				data.Error = "节点名称必须为 1-80 个字符"
			} else {
				data.Command = "curl -fsSL https://raw.githubusercontent.com/jaycen-0502/realm-panel/main/install_agent.sh -o /tmp/install_agent.sh && sudo bash /tmp/install_agent.sh " + shellQuote(data.MasterURL) + " " + shellQuote(a.token) + " " + shellQuote(data.NodeName)
			}
		}
	} else if r.Method != http.MethodGet {
		methodNotAllowed(w)
		return
	}
	if err := a.bindTmpl.Execute(w, data); err != nil {
		log.Printf("bind template: %v", err)
	}
}

func requestBaseURL(r *http.Request) string {
	scheme := "http"
	if r.TLS != nil || strings.EqualFold(r.Header.Get("X-Forwarded-Proto"), "https") {
		scheme = "https"
	}
	return scheme + "://" + r.Host
}

func shellQuote(s string) string { return "'" + strings.ReplaceAll(s, "'", "'\\''") + "'" }

func handleAppCSS(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		methodNotAllowed(w)
		return
	}
	w.Header().Set("Content-Type", "text/css; charset=utf-8")
	w.Header().Set("Cache-Control", "public, max-age=0, must-revalidate")
	_, _ = io.WriteString(w, appCSS)
}

func handleAppJS(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		methodNotAllowed(w)
		return
	}
	w.Header().Set("Content-Type", "application/javascript; charset=utf-8")
	w.Header().Set("Cache-Control", "public, max-age=0, must-revalidate")
	_, _ = io.WriteString(w, appJS)
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
	nodeList := make([]Node, 0, len(nodes))
	onlineCount := 0
	for _, node := range nodes {
		nodeList = append(nodeList, node)
		if !node.LastSeen.IsZero() && time.Since(node.LastSeen) < 150*time.Second {
			onlineCount++
		}
	}
	sort.Slice(nodeList, func(i, j int) bool { return strings.ToLower(nodeList[i].Name) < strings.ToLower(nodeList[j].Name) })
	sort.Slice(rules, func(i, j int) bool { return rules[i].CreatedAt.After(rules[j].CreatedAt) })
	msg := r.URL.Query().Get("msg")
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := a.tmpl.Execute(w, map[string]any{"Nodes": nodes, "NodeList": nodeList, "Rules": rules, "Message": msg, "MessageKind": r.URL.Query().Get("kind"), "NodeCount": len(nodes), "OnlineCount": onlineCount, "RuleCount": len(rules)}); err != nil {
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
		http.Redirect(w, r, "/?kind=error&msg="+url.QueryEscape(msg), http.StatusSeeOther)
	}
}
func (a *App) actionOK(w http.ResponseWriter, r *http.Request, msg string) {
	if wantsJSON(r) {
		writeJSON(w, 200, map[string]any{"ok": true})
	} else {
		http.Redirect(w, r, "/?kind=success&msg="+url.QueryEscape(msg), http.StatusSeeOther)
	}
}

func relativeTime(t time.Time) string {
	if t.IsZero() {
		return "从未连接"
	}
	d := time.Since(t)
	if d < 0 {
		d = 0
	}
	switch {
	case d < 10*time.Second:
		return "刚刚"
	case d < time.Minute:
		return fmt.Sprintf("%d 秒前", int(d.Seconds()))
	case d < time.Hour:
		return fmt.Sprintf("%d 分钟前", int(d.Minutes()))
	case d < 24*time.Hour:
		return fmt.Sprintf("%d 小时前", int(d.Hours()))
	default:
		return fmt.Sprintf("%d 天前", int(d.Hours()/24))
	}
}

const loginHTML = `<!doctype html>
<html lang="zh-CN"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta name="color-scheme" content="light dark"><title>登录 · Realm Console</title><link rel="stylesheet" href="/static/app.css"><script defer src="/static/app.js"></script></head>
<body class="auth-page"><a class="skip-link" href="#main">跳到登录表单</a><main id="main" class="auth-shell">
<section class="auth-brand" aria-labelledby="brand-title"><div class="brand-mark brand-mark--large" aria-hidden="true"><span></span><span></span><span></span></div><p class="eyebrow">DISTRIBUTED RELAY CONTROL</p><h1 id="brand-title">Realm<br>Console</h1><p class="auth-lead">轻量、可靠的分布式端口转发控制台。控制平面离线时，节点转发仍持续运行。</p><div class="trust-list"><div><span class="trust-dot"></span>本地配置持久化</div><div><span class="trust-dot"></span>加密签名指令</div><div><span class="trust-dot"></span>数据面独立运行</div></div></section>
<section class="auth-panel"><div class="auth-card"><div class="section-kicker">安全访问</div><h2>登录管理面板</h2><p class="muted">使用安装时设置的管理员凭据。</p>{{if .Error}}<div class="notice notice--error" role="alert">{{.Error}}</div>{{end}}<form method="post" data-loading><div class="field"><label for="username">管理员用户名</label><input id="username" name="username" type="text" autocomplete="username" spellcheck="false" required autofocus></div><div class="field"><label for="password">管理密码</label><div class="password-field"><input id="password" name="password" type="password" autocomplete="current-password" required><button class="password-toggle" id="password-toggle" type="button" aria-controls="password" aria-pressed="false">显示</button></div></div><button class="button button--primary button--wide" type="submit"><span>进入控制台</span><svg aria-hidden="true" viewBox="0 0 24 24"><path d="m9 18 6-6-6-6"/></svg></button></form><p class="auth-footnote">登录请求受频率限制，凭据仅保存在主控服务器。</p></div></section>
</main></body></html>`

const pageHTML = `<!doctype html>
<html lang="zh-CN"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta name="color-scheme" content="light dark"><title>Realm Console</title><link rel="stylesheet" href="/static/app.css"><script defer src="/static/app.js"></script></head>
<body><a class="skip-link" href="#main">跳到主要内容</a><header class="topbar"><div class="topbar__inner"><a class="brand" href="/" aria-label="Realm Console 首页"><span class="brand-mark" aria-hidden="true"><span></span><span></span><span></span></span><span><strong>Realm</strong><small>Console</small></span></a><nav class="topnav" aria-label="主要操作"><a class="button button--primary" href="/bind" target="_blank" rel="noopener" aria-label="绑定新节点"><svg aria-hidden="true" viewBox="0 0 24 24"><path d="M12 5v14M5 12h14"/></svg><span>绑定新节点</span></a><a class="button button--ghost" href="/logout">退出</a></nav></div></header>
<main id="main" class="container"><section class="page-heading"><div><p class="eyebrow">OPERATIONS OVERVIEW</p><h1>转发管理</h1><p>集中管理节点和规则，Realm 数据面独立运行。</p></div><div class="system-state"><span class="pulse" aria-hidden="true"></span><span>控制台运行中</span></div></section>
{{if .Message}}<div class="notice {{if eq .MessageKind "error"}}notice--error{{else}}notice--success{{end}}" role="status" aria-live="polite">{{.Message}}</div>{{end}}
<section class="stats" aria-label="系统概览"><article class="stat"><span class="stat__label">已绑定节点</span><strong>{{.NodeCount}}</strong><span class="stat__meta">全部受控端</span></article><article class="stat"><span class="stat__label">在线节点</span><strong>{{.OnlineCount}}</strong><span class="stat__meta"><i class="status-dot status-dot--online"></i>150 秒内有心跳</span></article><article class="stat"><span class="stat__label">生效规则</span><strong>{{.RuleCount}}</strong><span class="stat__meta">持久化转发配置</span></article></section>
<section class="panel panel--accent" aria-labelledby="add-rule-title"><div class="panel__header"><div><p class="section-kicker">QUICK ACTION</p><h2 id="add-rule-title">添加转发规则</h2></div><p>选择节点并定义监听端与目标端。</p></div><form class="rule-form" method="post" action="/api/add_rule" data-loading><div class="field"><label for="node_id">执行节点</label><select id="node_id" name="node_id" required><option value="">请选择节点</option>{{range .NodeList}}<option value="{{.ID}}">{{.Name}} · {{.IP}}</option>{{end}}</select></div><div class="field"><label for="listen">本机监听</label><input id="listen" name="listen" value="0.0.0.0:5000" placeholder="0.0.0.0:5000" inputmode="url" spellcheck="false" required><small>节点开放的地址与端口</small></div><div class="field"><label for="remote">转发目标</label><input id="remote" name="remote" placeholder="example.com:443" inputmode="url" spellcheck="false" required><small>目标 IP、域名及端口</small></div><button class="button button--primary rule-submit" type="submit"><svg aria-hidden="true" viewBox="0 0 24 24"><path d="M5 12h14M13 6l6 6-6 6"/></svg><span>保存并应用</span></button></form></section>
<section class="panel" aria-labelledby="nodes-title"><div class="panel__header"><div><p class="section-kicker">INFRASTRUCTURE</p><h2 id="nodes-title">节点</h2></div><span class="count-badge">{{.NodeCount}} 个节点</span></div><div class="table-wrap"><table><thead><tr><th scope="col">状态</th><th scope="col">节点名称</th><th scope="col">节点 IP</th><th scope="col">Agent 地址</th><th scope="col">最后心跳</th></tr></thead><tbody>{{range .NodeList}}<tr><td data-label="状态">{{if online .LastSeen}}<span class="status status--online"><i></i>在线</span>{{else}}<span class="status status--offline"><i></i>离线</span>{{end}}</td><td data-label="节点名称"><strong>{{.Name}}</strong></td><td data-label="节点 IP"><code>{{.IP}}</code></td><td data-label="Agent 地址"><code>{{.AgentURL}}</code></td><td data-label="最后心跳" class="muted">{{age .LastSeen}}</td></tr>{{else}}<tr><td colspan="5"><div class="empty-state"><svg aria-hidden="true" viewBox="0 0 24 24"><rect x="4" y="4" width="16" height="6" rx="1"/><rect x="4" y="14" width="16" height="6" rx="1"/><path d="M8 7h.01M8 17h.01"/></svg><h3>尚未绑定节点</h3><p>生成一键命令并在目标服务器执行，节点将自动出现在这里。</p><a class="button button--secondary" href="/bind" target="_blank" rel="noopener">生成绑定命令</a></div></td></tr>{{end}}</tbody></table></div></section>
<section class="panel" aria-labelledby="rules-title"><div class="panel__header"><div><p class="section-kicker">ROUTING</p><h2 id="rules-title">转发规则</h2></div><span class="count-badge">{{.RuleCount}} 条规则</span></div><div class="table-wrap"><table><thead><tr><th scope="col">节点</th><th scope="col">监听地址</th><th scope="col">目标地址</th><th scope="col"><span class="sr-only">操作</span></th></tr></thead><tbody>{{range .Rules}}<tr><td data-label="节点"><strong>{{nodeName $.Nodes .NodeID}}</strong></td><td data-label="监听地址"><code class="endpoint endpoint--listen">{{.Listen}}</code></td><td data-label="目标地址"><code class="endpoint">{{.Remote}}</code></td><td data-label="操作" class="table-action"><form method="post" action="/api/delete_rule" data-confirm="确定删除这条转发规则吗？删除后节点将立即重新加载配置。" data-loading><input type="hidden" name="id" value="{{.ID}}"><button class="button button--danger-ghost" type="submit"><svg aria-hidden="true" viewBox="0 0 24 24"><path d="M3 6h18M8 6V4h8v2M19 6l-1 14H6L5 6M10 10v6M14 10v6"/></svg><span>删除</span></button></form></td></tr>{{else}}<tr><td colspan="4"><div class="empty-state empty-state--compact"><svg aria-hidden="true" viewBox="0 0 24 24"><path d="M5 7h9a4 4 0 0 1 4 4v6M15 14l3 3 3-3M9 17H7a4 4 0 0 1-4-4V7M6 10 3 7 0 10"/></svg><h3>暂无转发规则</h3><p>绑定节点后，可从上方快速创建第一条规则。</p></div></td></tr>{{end}}</tbody></table></div></section>
<footer class="footer"><span>Realm Console</span><span>控制平面离线不会中断既有转发</span></footer></main></body></html>`

const bindPageHTML = `<!doctype html>
<html lang="zh-CN"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta name="color-scheme" content="light dark"><title>绑定新节点 · Realm Console</title><link rel="stylesheet" href="/static/app.css"><script defer src="/static/app.js"></script></head>
<body><a class="skip-link" href="#main">跳到主要内容</a><header class="topbar"><div class="topbar__inner"><a class="brand" href="/"><span class="brand-mark" aria-hidden="true"><span></span><span></span><span></span></span><span><strong>Realm</strong><small>Console</small></span></a><a class="button button--ghost" href="/"><svg aria-hidden="true" viewBox="0 0 24 24"><path d="m15 18-6-6 6-6"/></svg><span>返回面板</span></a></div></header><main id="main" class="container container--narrow"><section class="page-heading"><div><p class="eyebrow">NODE ONBOARDING</p><h1>绑定新节点</h1><p>生成一次性展示的安装命令，并在目标服务器执行。</p></div><div class="step-chip">第 1 步，共 2 步</div></section>
<section class="panel onboarding"><div class="security-note"><svg aria-hidden="true" viewBox="0 0 24 24"><path d="M12 3 4 6v5c0 5 3.4 8.5 8 10 4.6-1.5 8-5 8-10V6l-8-3Z"/><path d="m9 12 2 2 4-4"/></svg><div><strong>安全提示</strong><p>Token 只在当前登录页面临时展示，响应已禁止浏览器缓存。请勿将生成的命令发送到公开渠道。</p></div></div>{{if .Error}}<div class="notice notice--error" role="alert">{{.Error}}</div>{{end}}<form method="post" data-loading><div class="form-grid"><div class="field"><label for="master_url">主控地址</label><input id="master_url" name="master_url" value="{{.MasterURL}}" placeholder="https://panel.example.com:6800" inputmode="url" spellcheck="false" required><small>外网节点请填写公网 IP 或 HTTPS 域名</small></div><div class="field"><label for="node_name">节点名称</label><input id="node_name" name="node_name" value="{{.NodeName}}" placeholder="例如：香港节点-A" maxlength="80" autocomplete="off" required><small>建议使用地区与用途命名，便于识别</small></div></div><button class="button button--primary" type="submit"><svg aria-hidden="true" viewBox="0 0 24 24"><path d="M8 9 4 12l4 3M16 9l4 3-4 3M14 5l-4 14"/></svg><span>生成一键绑定命令</span></button></form></section>
{{if .Command}}<section class="panel command-panel" aria-labelledby="command-title"><div class="panel__header"><div><p class="section-kicker">STEP 2</p><h2 id="command-title">在节点服务器执行</h2></div><span class="status status--online"><i></i>命令已生成</span></div><div class="command-box"><textarea id="command" readonly aria-label="一键绑定命令">{{.Command}}</textarea><button id="copy" class="button button--secondary" type="button"><svg aria-hidden="true" viewBox="0 0 24 24"><rect x="8" y="8" width="12" height="12" rx="2"/><path d="M16 8V6a2 2 0 0 0-2-2H6a2 2 0 0 0-2 2v8a2 2 0 0 0 2 2h2"/></svg><span>复制命令</span></button></div><p id="copy-status" class="helper" aria-live="polite">执行完成后返回主面板刷新，节点通常会在几秒内出现。</p></section>{{end}}</main></body></html>`

const appJS = `document.addEventListener("DOMContentLoaded",()=>{const toggle=document.getElementById("password-toggle"),password=document.getElementById("password");if(toggle&&password)toggle.addEventListener("click",()=>{const show=password.type==="password";password.type=show?"text":"password";toggle.textContent=show?"隐藏":"显示";toggle.setAttribute("aria-pressed",String(show))});document.querySelectorAll("form[data-loading]").forEach(form=>form.addEventListener("submit",event=>{const message=form.dataset.confirm;if(message&&!window.confirm(message)){event.preventDefault();return}const button=form.querySelector('button[type="submit"]');if(button){button.disabled=true;button.setAttribute("aria-busy","true");const label=button.querySelector("span");if(label)label.textContent="处理中…"}}));const copy=document.getElementById("copy"),command=document.getElementById("command"),status=document.getElementById("copy-status");if(copy&&command)copy.addEventListener("click",async()=>{let ok=false;try{await navigator.clipboard.writeText(command.value);ok=true}catch(e){command.focus();command.select();ok=document.execCommand("copy")}if(ok){const label=copy.querySelector("span");if(label)label.textContent="已复制";copy.classList.add("is-success");if(status)status.textContent="命令已复制，可直接粘贴到节点终端执行。"}})});`

const appCSS = `:root{color-scheme:light;--bg:#f4f7f9;--surface:#fff;--surface-2:#f8fafb;--text:#14212b;--muted:#586875;--faint:#788895;--border:#dce4e9;--border-strong:#c7d2da;--primary:#075f65;--primary-hover:#064f54;--primary-soft:#e3f2f1;--accent:#e36b2c;--success:#18794e;--success-soft:#e8f5ee;--danger:#c43d3d;--danger-soft:#fcecec;--code:#edf3f5;--shadow:0 1px 2px rgba(20,33,43,.04),0 8px 24px rgba(20,33,43,.055);--radius:12px;--fast:140ms;--normal:220ms;--font:-apple-system,BlinkMacSystemFont,"Segoe UI","PingFang SC","Microsoft YaHei",sans-serif;--mono:"SFMono-Regular",Consolas,"Liberation Mono",monospace}*{box-sizing:border-box}html{scroll-behavior:smooth}body{margin:0;min-width:320px;background:var(--bg);color:var(--text);font:400 16px/1.55 var(--font);-webkit-font-smoothing:antialiased}body:before{content:"";position:fixed;inset:0;z-index:-1;pointer-events:none;background-image:linear-gradient(rgba(7,95,101,.025) 1px,transparent 1px),linear-gradient(90deg,rgba(7,95,101,.025) 1px,transparent 1px);background-size:32px 32px}a{color:inherit}button,input,select,textarea{font:inherit}button,a{touch-action:manipulation}.skip-link{position:fixed;z-index:1000;left:16px;top:8px;transform:translateY(-150%);padding:10px 14px;background:var(--text);color:var(--surface);border-radius:8px}.skip-link:focus{transform:none}.sr-only{position:absolute;width:1px;height:1px;padding:0;margin:-1px;overflow:hidden;clip:rect(0,0,0,0);white-space:nowrap;border:0}:focus-visible{outline:3px solid rgba(227,107,44,.75);outline-offset:3px}.topbar{position:sticky;top:0;z-index:20;border-bottom:1px solid rgba(199,210,218,.82);background:rgba(244,247,249,.9);backdrop-filter:blur(14px)}.topbar__inner{width:min(1180px,calc(100% - 40px));height:72px;margin:auto;display:flex;align-items:center;justify-content:space-between}.brand{display:flex;align-items:center;gap:11px;text-decoration:none}.brand>span:last-child{display:flex;align-items:baseline;gap:6px}.brand strong{font-size:18px;letter-spacing:-.02em}.brand small{color:var(--muted);font-size:12px;text-transform:uppercase;letter-spacing:.14em}.brand-mark{display:inline-flex;align-items:flex-end;gap:3px;width:29px;height:29px;padding:6px;background:var(--primary);border-radius:8px}.brand-mark span{display:block;width:4px;background:#fff;border-radius:2px}.brand-mark span:nth-child(1){height:7px}.brand-mark span:nth-child(2){height:15px}.brand-mark span:nth-child(3){height:11px}.brand-mark--large{width:48px;height:48px;padding:10px;gap:5px;border-radius:12px}.brand-mark--large span{width:6px}.brand-mark--large span:nth-child(1){height:12px}.brand-mark--large span:nth-child(2){height:26px}.brand-mark--large span:nth-child(3){height:19px}.topnav{display:flex;align-items:center;gap:8px}.container{width:min(1180px,calc(100% - 40px));margin:0 auto;padding:48px 0 32px}.container--narrow{width:min(860px,calc(100% - 40px))}.page-heading{display:flex;align-items:flex-end;justify-content:space-between;gap:24px;margin-bottom:28px}.page-heading h1{margin:3px 0 4px;font-size:clamp(30px,4vw,44px);line-height:1.15;letter-spacing:-.04em}.page-heading p{margin:0;color:var(--muted)}.eyebrow,.section-kicker{margin:0!important;color:var(--primary)!important;font-size:11px!important;font-weight:750;letter-spacing:.16em}.system-state,.step-chip{display:flex;align-items:center;gap:9px;white-space:nowrap;padding:8px 12px;border:1px solid var(--border);border-radius:999px;background:var(--surface);color:var(--muted);font-size:13px}.pulse{width:8px;height:8px;border-radius:50%;background:var(--success);box-shadow:0 0 0 4px var(--success-soft)}.stats{display:grid;grid-template-columns:repeat(3,1fr);gap:12px;margin-bottom:20px}.stat{position:relative;overflow:hidden;padding:20px 22px;border:1px solid var(--border);border-radius:var(--radius);background:var(--surface);box-shadow:0 1px 2px rgba(20,33,43,.025)}.stat:after{content:"";position:absolute;right:0;top:0;width:3px;height:100%;background:var(--primary);opacity:.72}.stat__label{display:block;color:var(--muted);font-size:13px;font-weight:650}.stat strong{display:block;margin:4px 0;font:700 34px/1.2 var(--mono);letter-spacing:-.04em}.stat__meta{display:flex;align-items:center;gap:6px;color:var(--faint);font-size:12px}.status-dot{display:inline-block;width:7px;height:7px;border-radius:50%}.status-dot--online{background:var(--success)}.panel{margin-bottom:16px;border:1px solid var(--border);border-radius:var(--radius);background:var(--surface);box-shadow:var(--shadow);overflow:hidden}.panel--accent{border-top:3px solid var(--primary)}.panel__header{min-height:78px;padding:20px 22px;display:flex;align-items:center;justify-content:space-between;gap:20px;border-bottom:1px solid var(--border)}.panel__header h2{margin:2px 0 0;font-size:19px;letter-spacing:-.02em}.panel__header>p{max-width:380px;margin:0;color:var(--muted);font-size:13px}.count-badge{padding:5px 9px;border:1px solid var(--border);border-radius:999px;background:var(--surface-2);color:var(--muted);font:600 12px var(--mono)}.rule-form{display:grid;grid-template-columns:1.15fr 1fr 1fr auto;align-items:end;gap:14px;padding:22px}.field{min-width:0}.field label{display:block;margin-bottom:7px;font-size:13px;font-weight:700}.field small,.helper{display:block;margin-top:6px;color:var(--faint);font-size:12px}.field input,.field select,.field textarea{width:100%;min-height:44px;border:1px solid var(--border-strong);border-radius:8px;background:var(--surface);color:var(--text);padding:9px 11px;transition:border-color var(--fast),box-shadow var(--fast),background var(--fast)}.field input:hover,.field select:hover,.field textarea:hover{border-color:#9caeb9}.field input:focus,.field select:focus,.field textarea:focus{border-color:var(--primary);box-shadow:0 0 0 3px rgba(7,95,101,.13);outline:none}.field input::placeholder,.field textarea::placeholder{color:#8b99a4}.button{min-height:44px;display:inline-flex;align-items:center;justify-content:center;gap:8px;border:1px solid transparent;border-radius:8px;padding:9px 14px;font-weight:700;font-size:14px;line-height:1;text-decoration:none;cursor:pointer;transition:background var(--fast),border-color var(--fast),color var(--fast),box-shadow var(--fast),opacity var(--fast)}.button svg{width:17px;height:17px;fill:none;stroke:currentColor;stroke-width:1.8;stroke-linecap:round;stroke-linejoin:round}.button--primary{background:var(--primary);color:#fff;box-shadow:0 1px 1px rgba(0,0,0,.06)}.button--primary:hover{background:var(--primary-hover)}.button--secondary{border-color:var(--border-strong);background:var(--surface);color:var(--text)}.button--secondary:hover,.button--ghost:hover{background:var(--surface-2);border-color:var(--border)}.button--ghost{border-color:transparent;background:transparent;color:var(--muted)}.button--danger-ghost{min-height:36px;padding:7px 9px;background:transparent;color:var(--danger)}.button--danger-ghost:hover{background:var(--danger-soft)}.button--wide{width:100%;margin-top:8px}.button:disabled{cursor:not-allowed;opacity:.58}.rule-submit{margin-bottom:23px}.table-wrap{overflow-x:auto}table{width:100%;border-collapse:collapse;text-align:left}th{padding:11px 22px;background:var(--surface-2);color:var(--faint);font-size:11px;font-weight:750;letter-spacing:.08em;text-transform:uppercase}td{padding:15px 22px;border-top:1px solid var(--border);font-size:14px;vertical-align:middle}tbody tr{transition:background var(--fast)}tbody tr:hover{background:rgba(7,95,101,.025)}td code{font:500 12px/1.5 var(--mono);overflow-wrap:anywhere}.endpoint{display:inline-block;padding:4px 7px;border-radius:5px;background:var(--code);color:var(--text)}.endpoint--listen{box-shadow:inset 2px 0 var(--primary)}.table-action{text-align:right}.table-action form{display:inline}.status{display:inline-flex;align-items:center;gap:7px;white-space:nowrap;font-size:12px;font-weight:700}.status i{width:7px;height:7px;border-radius:50%}.status--online{color:var(--success)}.status--online i{background:var(--success);box-shadow:0 0 0 3px var(--success-soft)}.status--offline{color:var(--faint)}.status--offline i{background:var(--faint)}.empty-state{max-width:460px;margin:auto;padding:38px 20px;text-align:center}.empty-state svg{width:34px;height:34px;fill:none;stroke:var(--primary);stroke-width:1.5;stroke-linecap:round;stroke-linejoin:round}.empty-state h3{margin:12px 0 4px;font-size:16px}.empty-state p{margin:0 0 16px;color:var(--muted);font-size:13px}.empty-state--compact{padding:28px 20px}.notice{margin-bottom:16px;padding:12px 14px;border:1px solid;border-radius:8px;font-size:14px}.notice--success{border-color:#afd9c2;background:var(--success-soft);color:#12633f}.notice--error{border-color:#edb8b8;background:var(--danger-soft);color:#9e2929}.footer{display:flex;justify-content:space-between;gap:16px;padding:16px 2px 0;color:var(--faint);font-size:12px}.onboarding{padding:22px}.security-note{display:flex;gap:12px;margin-bottom:22px;padding:15px;border:1px solid #bad9d8;border-radius:9px;background:var(--primary-soft)}.security-note svg{flex:0 0 auto;width:22px;height:22px;fill:none;stroke:var(--primary);stroke-width:1.8;stroke-linecap:round;stroke-linejoin:round}.security-note strong{font-size:13px}.security-note p{margin:2px 0 0;color:var(--muted);font-size:12px}.form-grid{display:grid;grid-template-columns:1fr 1fr;gap:16px;margin-bottom:18px}.command-panel{padding-bottom:20px}.command-box{display:grid;grid-template-columns:1fr auto;align-items:stretch;gap:10px;padding:20px 22px 4px}.command-box textarea{width:100%;min-height:132px;resize:vertical;border:1px solid var(--border-strong);border-radius:8px;background:#14212b;color:#dcebed;padding:14px;font:12px/1.65 var(--mono);overflow-wrap:anywhere}.command-box .button{align-self:end}.command-panel>.helper{padding:4px 22px 0}.is-success{border-color:var(--success)!important;color:var(--success)!important}.auth-page{background:#10262a}.auth-page:before{background-image:linear-gradient(rgba(255,255,255,.025) 1px,transparent 1px),linear-gradient(90deg,rgba(255,255,255,.025) 1px,transparent 1px)}.auth-shell{min-height:100dvh;display:grid;grid-template-columns:minmax(320px,.9fr) minmax(420px,1.1fr)}.auth-brand{display:flex;flex-direction:column;justify-content:center;padding:clamp(40px,8vw,110px);color:#eff8f7}.auth-brand .eyebrow{margin-top:28px!important;color:#8dc8c3!important}.auth-brand h1{margin:8px 0 20px;font-size:clamp(54px,7vw,92px);line-height:.9;letter-spacing:-.065em}.auth-lead{max-width:480px;color:#b6ccca;font-size:17px}.trust-list{display:flex;flex-wrap:wrap;gap:12px 22px;margin-top:34px;color:#91aaa8;font-size:12px}.trust-list>div{display:flex;align-items:center;gap:7px}.trust-dot{width:6px;height:6px;border-radius:50%;background:#6fc2b9}.auth-panel{display:grid;place-items:center;padding:28px;background:var(--bg);border-radius:20px 0 0 20px}.auth-card{width:min(420px,100%);padding:34px;border:1px solid var(--border);border-radius:14px;background:var(--surface);box-shadow:var(--shadow)}.auth-card h2{margin:4px 0;font-size:26px;letter-spacing:-.035em}.auth-card>.muted{margin:0 0 24px}.auth-card .field{margin-bottom:17px}.password-field{position:relative}.password-field input{padding-right:68px}.password-toggle{position:absolute;right:6px;top:6px;min-width:54px;height:32px;border:0;border-radius:6px;background:transparent;color:var(--primary);font-size:12px;font-weight:700;cursor:pointer}.password-toggle:hover{background:var(--primary-soft)}.auth-footnote{margin:18px 0 0;color:var(--faint);font-size:11px;text-align:center}
@media(prefers-color-scheme:dark){:root{color-scheme:dark;--bg:#11191d;--surface:#182329;--surface-2:#1c292f;--text:#e8f0f2;--muted:#a9b8be;--faint:#899aa2;--border:#2b3a42;--border-strong:#3b4c55;--primary:#68c3bb;--primary-hover:#7dd1ca;--primary-soft:#183d3e;--success:#67ce99;--success-soft:#17382a;--danger:#ff8585;--danger-soft:#3d2427;--code:#223138;--shadow:0 1px 2px rgba(0,0,0,.15),0 12px 28px rgba(0,0,0,.18)}.button--primary{color:#09272a}.notice--success{color:#8de0b3;border-color:#315e46}.notice--error{color:#ffaaaa;border-color:#66383c}.security-note{border-color:#315c5c}.command-box textarea{background:#0c1316}.auth-panel{background:var(--bg)}}
@media(max-width:900px){.rule-form{grid-template-columns:1fr 1fr}.rule-submit{margin:0}.auth-shell{grid-template-columns:1fr}.auth-brand{display:none}.auth-panel{border-radius:0;min-height:100dvh}.stats{grid-template-columns:repeat(3,1fr)}}
@media(max-width:680px){body{font-size:16px}.topbar__inner,.container,.container--narrow{width:min(100% - 24px,1180px)}.topbar__inner{height:64px}.brand small{display:none}.topnav{gap:2px}.topnav .button--ghost{padding-inline:9px;width:auto}.container{padding-top:28px}.page-heading{align-items:flex-start;flex-direction:column}.system-state,.step-chip{align-self:flex-start}.stats{grid-template-columns:1fr}.stat{padding:16px 18px}.stat strong{font-size:28px}.panel__header{align-items:flex-start;padding:17px 16px}.panel__header>p{display:none}.rule-form,.form-grid{grid-template-columns:1fr;padding:18px 16px}.onboarding{padding:16px}.rule-submit{width:100%}.table-wrap{overflow:visible}table,thead,tbody,tr,th,td{display:block}thead{position:absolute;width:1px;height:1px;overflow:hidden;clip:rect(0,0,0,0)}tbody tr{padding:13px 16px;border-top:1px solid var(--border)}tbody tr:first-child{border-top:0}td{display:grid;grid-template-columns:minmax(92px,.42fr) 1fr;gap:12px;padding:6px 0;border:0;align-items:start}td:before{content:attr(data-label);color:var(--faint);font-size:11px;font-weight:700;letter-spacing:.06em;text-transform:uppercase}td[colspan]{display:block;padding:0}td[colspan]:before{display:none}.table-action{text-align:left}.table-action form{display:block}.button--danger-ghost{width:100%;justify-content:flex-start;padding-left:0}.empty-state{padding:30px 8px}.footer{flex-direction:column}.command-box{grid-template-columns:1fr;padding:16px 16px 4px}.command-box .button{width:100%}.command-panel>.helper{padding-inline:16px}.auth-panel{padding:16px}.auth-card{padding:26px 20px}.topnav .button--primary span{display:none}.topnav .button--primary{width:44px;padding:0}.security-note{align-items:flex-start}}
@media(prefers-color-scheme:light){:root{--faint:#596b77}}.button:active{box-shadow:none;filter:brightness(.94)}
@media(prefers-reduced-motion:reduce){*,*:before,*:after{scroll-behavior:auto!important;transition-duration:.01ms!important;animation-duration:.01ms!important;animation-iteration-count:1!important}}`
