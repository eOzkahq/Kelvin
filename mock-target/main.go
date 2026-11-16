package main

import (
	"encoding/json"
	"fmt"
	"html"
	"log"
	"net/http"
	"os"
	"time"
)

type HealthResponse struct {
	Status    string    `json:"status"`
	Service   string    `json:"service"`
	Timestamp time.Time `json:"timestamp"`
}

func main() {
	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}

	mux := http.NewServeMux()

	// 1. Healthcheck endpoint
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(HealthResponse{
			Status:    "healthy",
			Service:   "kelvin-mock-target",
			Timestamp: time.Now().UTC(),
		})
	})

	// 2. Safe index endpoint
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = fmt.Fprintln(w, `<!DOCTYPE html>
<html>
<head><title>Kelvin Mock Target Lab</title></head>
<body>
  <h1>Kelvin Mock Vulnerable Target Lab</h1>
  <p>This is an isolated, sandboxed local service for safe vulnerability scanner testing.</p>
  <ul>
    <li><a href="/healthz">/healthz</a> - Health check</li>
    <li><a href="/vulnerable/headers">/vulnerable/headers</a> - Missing security headers</li>
    <li><a href="/vulnerable/xss?q=test">/vulnerable/xss</a> - Reflected XSS endpoint</li>
    <li><a href="/vulnerable/sqli?id=1">/vulnerable/sqli</a> - Mock SQL Injection endpoint</li>
    <li><a href="/vulnerable/info">/vulnerable/info</a> - Information disclosure</li>
  </ul>
</body>
</html>`)
	})

	// 3. Intentionally missing security headers & disclosing server info
	mux.HandleFunc("/vulnerable/headers", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Server", "Apache/2.4.41 (Ubuntu) Mock/1.0")
		w.Header().Set("X-Powered-By", "PHP/7.4.3")
		// Intentionally omitting: Strict-Transport-Security, X-Frame-Options, X-Content-Type-Options
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		_, _ = fmt.Fprintln(w, "Endpoint deliberately missing security headers (HSTS, CSP, X-Frame-Options, etc.).")
	})

	// 4. Intentionally vulnerable to Reflected XSS
	mux.HandleFunc("/vulnerable/xss", func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query().Get("q")
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		// Intentionally unescaped input for scanner detection test
		_, _ = fmt.Fprintf(w, "<html><body><h2>Search Query:</h2><div>%s</div><!-- Escaped preview: %s --></body></html>", q, html.EscapeString(q))
	})

	// 5. Intentionally vulnerable to mock SQL Injection (error-based response simulation)
	mux.HandleFunc("/vulnerable/sqli", func(w http.ResponseWriter, r *http.Request) {
		id := r.URL.Query().Get("id")
		w.Header().Set("Content-Type", "application/json")
		if id == "'" || id == "1' OR '1'='1" || id == "1'--" {
			w.WriteHeader(http.StatusInternalServerError)
			_, _ = fmt.Fprintln(w, `{"error":"syntax error at or near \"'\" at character 42","state":"42601","query":"SELECT * FROM mock_users WHERE id = '"}`)
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = fmt.Fprintf(w, `{"user":{"id":%q,"username":"test_analyst","role":"analyst"}}`, id)
	})

	// 6. Information disclosure endpoint
	mux.HandleFunc("/vulnerable/info", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = fmt.Fprintln(w, `{
  "system": "Kelvin Mock Lab Target",
  "debug": true,
  "internal_build": "mock-vuln-2026.1",
  "environment": "sandboxed-lab",
  "mock_credentials": {
    "api_key": "MOCK-SECRET-KEY-DO-NOT-USE-IN-PROD",
    "db_user": "mock_admin"
  }
}`)
	})

	// 7. Mock environment file for safe discovery testing
	mux.HandleFunc("/.env", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		_, _ = fmt.Fprintln(w, "APP_ENV=staging\nDB_PASSWORD=mock_insecure_password_123\nDATABASE_URL=postgres://mock:mock@localhost:5432/mock_db")
	})

	// 8. Mock robots.txt for discovery testing
	mux.HandleFunc("/robots.txt", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		_, _ = fmt.Fprintln(w, "User-agent: *\nDisallow: /admin\nDisallow: /vulnerable/")
	})

	addr := ":" + port
	log.Printf("[mock-target] Listening on %s ...", addr)
	if err := http.ListenAndServe(addr, mux); err != nil {
		log.Fatalf("[mock-target] Server error: %v", err)
	}
}

