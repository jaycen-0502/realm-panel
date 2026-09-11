package main

import (
	"bytes"
	"html/template"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestSameOriginAllowsMatchingOriginWithSameSiteMetadata(t *testing.T) {
	r := httptest.NewRequest("POST", "http://43.153.54.154:6800/bind", strings.NewReader("node_name=test"))
	r.Header.Set("Origin", "http://43.153.54.154:6800")
	r.Header.Set("Sec-Fetch-Site", "same-site")
	if !sameOrigin(r) {
		t.Fatal("matching Origin must not be rejected because Sec-Fetch-Site says same-site")
	}
}

func TestSameOriginRejectsUntrustedRequests(t *testing.T) {
	tests := []struct {
		name   string
		origin string
		site   string
	}{
		{name: "different origin", origin: "http://attacker.example"},
		{name: "cross-site without origin", site: "cross-site"},
		{name: "same-site without verifiable origin", site: "same-site"},
		{name: "opaque origin", origin: "null"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			r := httptest.NewRequest("POST", "http://43.153.54.154:6800/bind", nil)
			if tc.origin != "" {
				r.Header.Set("Origin", tc.origin)
			}
			if tc.site != "" {
				r.Header.Set("Sec-Fetch-Site", tc.site)
			}
			if sameOrigin(r) {
				t.Fatal("untrusted request was accepted")
			}
		})
	}
}

func TestUITemplatesRender(t *testing.T) {
	funcs := template.FuncMap{
		"age":    relativeTime,
		"online": func(time.Time) bool { return true },
		"nodeName": func(nodes map[string]Node, id string) string {
			return nodes[id].Name
		},
	}
	node := Node{ID: "node-1", Name: "测试节点", IP: "192.0.2.1", AgentURL: "http://192.0.2.1:6800", LastSeen: time.Now()}
	data := map[string]any{
		"Nodes": map[string]Node{node.ID: node}, "NodeList": []Node{node},
		"Rules":     []Rule{{ID: "rule-1", NodeID: node.ID, Listen: "0.0.0.0:5000", Remote: "example.com:443"}},
		"NodeCount": 1, "OnlineCount": 1, "RuleCount": 1,
	}
	tests := []struct {
		name, source string
		data         any
		want         []string
	}{
		{"login", loginHTML, nil, []string{"管理员用户名", "current-password", "/static/app.css"}},
		{"dashboard", pageHTML, data, []string{"测试节点", "example.com:443", "绑定新节点"}},
		{"bind", bindPageHTML, bindPageData{MasterURL: "https://panel.example.com:6800"}, []string{"主控地址", "节点名称", "安全提示"}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			tmpl := template.Must(template.New(tc.name).Funcs(funcs).Parse(tc.source))
			var out bytes.Buffer
			if err := tmpl.Execute(&out, tc.data); err != nil {
				t.Fatal(err)
			}
			for _, want := range tc.want {
				if !strings.Contains(out.String(), want) {
					t.Errorf("rendered template missing %q", want)
				}
			}
		})
	}
}

func TestUIAccessibilityAndPerformanceContracts(t *testing.T) {
	checks := map[string]bool{
		"reduced motion":  strings.Contains(appCSS, "prefers-reduced-motion"),
		"dark mode":       strings.Contains(appCSS, "prefers-color-scheme:dark"),
		"visible focus":   strings.Contains(appCSS, ":focus-visible"),
		"mobile layout":   strings.Contains(appCSS, "max-width:680px"),
		"no remote CSS":   !strings.Contains(appCSS, "@import"),
		"no inline style": !strings.Contains(pageHTML, "style="),
	}
	for name, ok := range checks {
		if !ok {
			t.Errorf("UI contract failed: %s", name)
		}
	}
}
