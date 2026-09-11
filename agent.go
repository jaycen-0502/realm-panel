// realm-agent: dependency-free receiver used on each managed Realm node.
package main

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
)

const tokenHeader = "X-Realm-Token"

type Rule struct {
	ID        string    `json:"id"`
	NodeID    string    `json:"node_id,omitempty"`
	Listen    string    `json:"listen"`
	Remote    string    `json:"remote"`
	CreatedAt time.Time `json:"created_at,omitempty"`
}

type Agent struct {
	mu         sync.Mutex
	token      string
	masterURL  string
	nodeName   string
	nodeIP     string
	listenAddr string
	publicURL  string
	configPath string
	statePath  string
	realmUnit  string
	rules      map[string]Rule
	client     *http.Client
	replay     *ReplayGuard
	limit      *RateLimiter
	masterIP   net.IP
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
	a := &Agent{
		token: mustEnv("REALM_TOKEN"), masterURL: strings.TrimRight(mustEnv("MASTER_URL"), "/"), nodeName: mustEnv("NODE_NAME"),
		listenAddr: getenv("AGENT_ADDR", ":6800"), configPath: getenv("REALM_CONFIG", "/etc/realm/config.toml"),
		statePath: getenv("AGENT_STATE", "/etc/realm/agent-rules.json"), realmUnit: getenv("REALM_SERVICE", "realm.service"),
		rules: map[string]Rule{}, client: &http.Client{Timeout: 12 * time.Second},
		replay: &ReplayGuard{seen: make(map[string]time.Time)},
		limit:  &RateLimiter{entries: make(map[string]rateEntry), limit: 120, window: time.Minute},
	}
	if len(a.token) < 32 {
		log.Fatal("REALM_TOKEN must be at least 32 characters")
	}
	a.nodeIP = os.Getenv("NODE_IP")
	if a.nodeIP == "" {
		a.nodeIP = discoverIP(a.masterURL)
	}
	a.publicURL = os.Getenv("AGENT_PUBLIC_URL")
	if a.publicURL == "" {
		a.publicURL = "http://" + net.JoinHostPort(a.nodeIP, portOnly(a.listenAddr))
	}
	a.masterIP = configuredMasterIP(a.masterURL)
	if a.masterIP != nil {
		log.Printf("agent API restricted to master source IP %s", a.masterIP)
	} else {
		log.Printf("warning: master host is not an IP; enforce source filtering with a firewall")
	}
	if err := a.loadState(); err != nil {
		log.Fatal(err)
	}
	changed, err := a.reconcileConfig()
	if err != nil {
		log.Fatal(err)
	}
	if changed && len(a.rules) > 0 {
		if err := restart(a.realmUnit); err != nil {
			log.Printf("startup config reconciliation could not restart Realm: %v", err)
		}
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/health", a.auth(a.handleHealth))
	mux.HandleFunc("/api/rules/add", a.auth(a.handleAdd))
	mux.HandleFunc("/api/rules/delete", a.auth(a.handleDelete))
	server := &http.Server{Addr: a.listenAddr, Handler: mux, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 15 * time.Second, WriteTimeout: 20 * time.Second, IdleTimeout: 60 * time.Second, MaxHeaderBytes: 16 << 10}
	go a.registrationLoop()
	log.Printf("realm agent %q listening on %s; advertising %s", a.nodeName, a.listenAddr, a.publicURL)
	log.Fatal(server.ListenAndServe())
}

func mustEnv(k string) string {
	v := strings.TrimSpace(os.Getenv(k))
	if v == "" {
		log.Fatalf("%s must be set", k)
	}
	return v
}
func getenv(k, fallback string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return fallback
}

func (a *Agent) auth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ip := net.ParseIP(remoteIP(r))
		if a.masterIP != nil && (ip == nil || !ip.Equal(a.masterIP)) {
			jsonError(w, "source not allowed", http.StatusForbidden)
			return
		}
		if !a.limit.allow(remoteIP(r)) {
			w.Header().Set("Retry-After", "60")
			jsonError(w, "too many requests", http.StatusTooManyRequests)
			return
		}
		if !a.verifySignedRequest(r) {
			jsonError(w, "invalid or replayed signature", 401)
			return
		}
		next(w, r)
	}
}

func configuredMasterIP(masterURL string) net.IP {
	if explicit := strings.TrimSpace(os.Getenv("MASTER_SOURCE_IP")); explicit != "" {
		return net.ParseIP(explicit)
	}
	u, err := url.Parse(masterURL)
	if err != nil {
		return nil
	}
	return net.ParseIP(u.Hostname())
}

func remoteIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err == nil {
		return host
	}
	return r.RemoteAddr
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
	if len(l.entries) > 1024 {
		for k, v := range l.entries {
			if now.Sub(v.window) >= l.window {
				delete(l.entries, k)
			}
		}
	}
	return e.count <= l.limit
}

func (a *Agent) verifySignedRequest(r *http.Request) bool {
	body, err := io.ReadAll(io.LimitReader(r.Body, (64<<10)+1))
	if err != nil || len(body) > 64<<10 {
		return false
	}
	r.Body = io.NopCloser(bytes.NewReader(body))
	ts, nonce := r.Header.Get("X-Realm-Timestamp"), r.Header.Get("X-Realm-Nonce")
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

func (a *Agent) handleHealth(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		jsonError(w, "method not allowed", 405)
		return
	}
	a.mu.Lock()
	count := len(a.rules)
	a.mu.Unlock()
	writeJSON(w, 200, map[string]any{"ok": true, "node": a.nodeName, "rules": count})
}

func (a *Agent) handleAdd(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		jsonError(w, "method not allowed", 405)
		return
	}
	var rule Rule
	if err := a.decodeCommand(r, &rule); err != nil {
		jsonError(w, err.Error(), 400)
		return
	}
	if rule.ID == "" || len(rule.ID) > 64 {
		jsonError(w, "invalid rule id", 400)
		return
	}
	if err := validateEndpoint(rule.Listen, true); err != nil {
		jsonError(w, "listen: "+err.Error(), 400)
		return
	}
	if err := validateEndpoint(rule.Remote, false); err != nil {
		jsonError(w, "remote: "+err.Error(), 400)
		return
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	for id, existing := range a.rules {
		if id != rule.ID && existing.Listen == rule.Listen {
			jsonError(w, "listen address already managed", 409)
			return
		}
	}
	old := cloneRules(a.rules)
	a.rules[rule.ID] = rule
	if err := a.commitAndRestart(old); err != nil {
		jsonError(w, err.Error(), 500)
		return
	}
	writeJSON(w, 200, map[string]any{"ok": true})
}

func (a *Agent) handleDelete(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		jsonError(w, "method not allowed", 405)
		return
	}
	var req struct {
		ID string `json:"id"`
	}
	if err := a.decodeCommand(r, &req); err != nil {
		jsonError(w, err.Error(), 400)
		return
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if _, ok := a.rules[req.ID]; !ok {
		jsonError(w, "rule not found", 404)
		return
	}
	old := cloneRules(a.rules)
	delete(a.rules, req.ID)
	if err := a.commitAndRestart(old); err != nil {
		jsonError(w, err.Error(), 500)
		return
	}
	writeJSON(w, 200, map[string]any{"ok": true})
}

func (a *Agent) commitAndRestart(old map[string]Rule) error {
	if err := a.saveState(); err != nil {
		a.rules = old
		return fmt.Errorf("save state: %w", err)
	}
	if err := a.writeConfig(); err != nil {
		a.rules = old
		_ = a.saveState()
		return fmt.Errorf("write config: %w", err)
	}
	if err := restart(a.realmUnit); err != nil {
		a.rules = old
		_ = a.saveState()
		_ = a.writeConfig()
		rollbackErr := restart(a.realmUnit)
		if rollbackErr != nil {
			return fmt.Errorf("restart failed: %v; rollback restart also failed: %v", err, rollbackErr)
		}
		return fmt.Errorf("restart failed; configuration rolled back: %w", err)
	}
	return nil
}

func restart(unit string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, "systemctl", "restart", unit).CombinedOutput()
	if err != nil {
		return fmt.Errorf("systemctl: %w: %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}

func (a *Agent) loadState() error {
	b, err := os.ReadFile(a.statePath)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	if len(bytes.TrimSpace(b)) == 0 {
		return nil
	}
	return json.Unmarshal(b, &a.rules)
}

func (a *Agent) saveState() error { return writeAtomicJSON(a.statePath, a.rules, 0600) }

func (a *Agent) renderConfig() []byte {
	var b strings.Builder
	b.WriteString("# Managed by realm-agent. Manual edits will be overwritten.\n\n[network]\nno_tcp = false\nuse_udp = true\n")
	ids := make([]string, 0, len(a.rules))
	for id := range a.rules {
		ids = append(ids, id)
	}
	sortStrings(ids)
	for _, id := range ids {
		r := a.rules[id]
		b.WriteString("\n# rule_id = ")
		b.WriteString(id)
		b.WriteString("\n[[endpoints]]\nlisten = ")
		b.WriteString(strconv.Quote(r.Listen))
		b.WriteString("\nremote = ")
		b.WriteString(strconv.Quote(r.Remote))
		b.WriteByte('\n')
	}
	return []byte(b.String())
}

func (a *Agent) writeConfig() error { return writeAtomic(a.configPath, a.renderConfig(), 0644) }

func (a *Agent) reconcileConfig() (bool, error) {
	desired := a.renderConfig()
	current, err := os.ReadFile(a.configPath)
	if err == nil && bytes.Equal(current, desired) {
		return false, nil
	}
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return false, err
	}
	return true, writeAtomic(a.configPath, desired, 0644)
}

func (a *Agent) registrationLoop() {
	for {
		if err := a.register(); err != nil {
			log.Printf("register: %v", err)
		}
		time.Sleep(60 * time.Second)
	}
}

func (a *Agent) register() error {
	payload := map[string]string{"name": a.nodeName, "ip": a.nodeIP, "agent_url": a.publicURL}
	b, _ := json.Marshal(payload)
	req, err := http.NewRequest(http.MethodPost, a.masterURL+"/api/register", bytes.NewReader(b))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
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

// decodeCommand authenticates the AES-256-GCM command envelope before parsing
// its JSON payload. Authentication of the HTTP caller is handled separately.
func (a *Agent) decodeCommand(r *http.Request, dst any) error {
	defer r.Body.Close()
	var envelope struct {
		Nonce      string `json:"nonce"`
		Ciphertext string `json:"ciphertext"`
	}
	d := json.NewDecoder(io.LimitReader(r.Body, 64<<10))
	d.DisallowUnknownFields()
	if err := d.Decode(&envelope); err != nil {
		return fmt.Errorf("invalid encrypted envelope: %w", err)
	}
	nonce, err := base64.RawStdEncoding.DecodeString(envelope.Nonce)
	if err != nil {
		return errors.New("invalid nonce")
	}
	ciphertext, err := base64.RawStdEncoding.DecodeString(envelope.Ciphertext)
	if err != nil {
		return errors.New("invalid ciphertext")
	}
	key := sha256.Sum256([]byte("realm-command-v1\x00" + a.token))
	block, err := aes.NewCipher(key[:])
	if err != nil {
		return err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return err
	}
	if len(nonce) != gcm.NonceSize() {
		return errors.New("invalid nonce size")
	}
	plaintext, err := gcm.Open(nil, nonce, ciphertext, []byte("realm-command-v1"))
	if err != nil {
		return errors.New("command authentication failed")
	}
	payloadDecoder := json.NewDecoder(bytes.NewReader(plaintext))
	payloadDecoder.DisallowUnknownFields()
	return payloadDecoder.Decode(dst)
}

func discoverIP(master string) string {
	u, err := url.Parse(master)
	if err == nil {
		host := u.Hostname()
		if host != "" {
			conn, err := net.Dial("udp", net.JoinHostPort(host, "80"))
			if err == nil {
				defer conn.Close()
				if a, ok := conn.LocalAddr().(*net.UDPAddr); ok {
					return a.IP.String()
				}
			}
		}
	}
	return "127.0.0.1"
}

func portOnly(addr string) string {
	_, port, err := net.SplitHostPort(addr)
	if err == nil && port != "" {
		return port
	}
	if strings.HasPrefix(addr, ":") {
		return strings.TrimPrefix(addr, ":")
	}
	return "6800"
}
func validateEndpoint(s string, listen bool) error {
	if len(s) < 2 || len(s) > 255 || strings.ContainsAny(s, "\r\n\t\"") {
		return errors.New("invalid format")
	}
	host, port, err := net.SplitHostPort(s)
	if err != nil {
		return errors.New("use host:port; wrap IPv6 in brackets")
	}
	p, err := strconv.Atoi(port)
	if err != nil || p < 1 || p > 65535 {
		return errors.New("port must be 1-65535")
	}
	if !listen && strings.TrimSpace(host) == "" {
		return errors.New("host is required")
	}
	return nil
}
func cloneRules(in map[string]Rule) map[string]Rule {
	out := make(map[string]Rule, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}
func sortStrings(v []string) {
	for i := 1; i < len(v); i++ {
		for j := i; j > 0 && v[j] < v[j-1]; j-- {
			v[j], v[j-1] = v[j-1], v[j]
		}
	}
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
func writeAtomicJSON(path string, v any, mode os.FileMode) error {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	return writeAtomic(path, append(b, '\n'), mode)
}
func writeAtomic(path string, b []byte, mode os.FileMode) error {
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return err
	}
	f, err := os.CreateTemp(filepath.Dir(path), ".realm-agent-*")
	if err != nil {
		return err
	}
	name := f.Name()
	defer os.Remove(name)
	if err = f.Chmod(mode); err == nil {
		_, err = f.Write(b)
	}
	if e := f.Sync(); err == nil {
		err = e
	}
	if e := f.Close(); err == nil {
		err = e
	}
	if err != nil {
		return err
	}
	return os.Rename(name, path)
}
