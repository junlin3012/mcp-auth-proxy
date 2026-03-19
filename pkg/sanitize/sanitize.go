package sanitize

import (
	"bytes"
	"encoding/json"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
)

// responseWriter wraps gin.ResponseWriter to capture and sanitize error responses
type responseWriter struct {
	gin.ResponseWriter
	body *bytes.Buffer
}

func (w *responseWriter) Write(b []byte) (int, error) {
	return w.body.Write(b)
}

// Middleware strips framework details (Pydantic, FastAPI) from error responses.
// Only modifies JSON responses that contain framework-identifying strings.
func Middleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		// Only sanitize responses for proxied requests (not auth endpoints)
		if !strings.HasPrefix(c.Request.URL.Path, "/mcp") &&
			!strings.HasPrefix(c.Request.URL.Path, "/servers/") &&
			!strings.HasPrefix(c.Request.URL.Path, "/gateways") &&
			!strings.HasPrefix(c.Request.URL.Path, "/tools") {
			c.Next()
			return
		}

		// Wrap the response writer to capture output
		w := &responseWriter{
			ResponseWriter: c.Writer,
			body:           &bytes.Buffer{},
		}
		c.Writer = w
		c.Next()

		body := w.body.Bytes()

		// Only sanitize error responses that leak framework info
		if w.Status() >= 400 && containsFrameworkLeak(body) {
			sanitized := sanitizeErrorResponse(body)
			c.Writer = w.ResponseWriter
			c.Writer.Header().Set("Content-Type", "application/json")
			c.Writer.WriteHeader(w.Status())
			c.Writer.Write(sanitized)
			return
		}

		// Pass through unchanged
		c.Writer = w.ResponseWriter
		c.Writer.WriteHeader(w.Status())
		c.Writer.Write(body)
	}
}

func containsFrameworkLeak(body []byte) bool {
	s := string(body)
	return strings.Contains(s, "pydantic") ||
		strings.Contains(s, "Pydantic") ||
		strings.Contains(s, "fastapi") ||
		strings.Contains(s, "FastAPI") ||
		strings.Contains(s, "errors.pydantic.dev")
}

func sanitizeErrorResponse(body []byte) []byte {
	// Try to parse as JSON-RPC error
	var rpcResp map[string]any
	if err := json.Unmarshal(body, &rpcResp); err != nil {
		// Not JSON — return generic error
		return []byte(`{"error":"Request validation failed"}`)
	}

	// If it's a JSON-RPC error, clean the message
	if errObj, ok := rpcResp["error"].(map[string]any); ok {
		if msg, ok := errObj["message"].(string); ok {
			// Strip pydantic URLs and model names
			cleaned := msg
			// Remove "For further information visit https://errors.pydantic.dev/..." lines
			lines := strings.Split(cleaned, "\n")
			var filtered []string
			for _, line := range lines {
				if strings.Contains(line, "errors.pydantic.dev") {
					continue
				}
				// Remove internal model references
				line = strings.ReplaceAll(line, "JSONRPCRequest.", "")
				line = strings.ReplaceAll(line, "JSONRPCNotification.", "")
				line = strings.ReplaceAll(line, "JSONRPCResponse.", "")
				line = strings.ReplaceAll(line, "JSONRPCError.", "")
				line = strings.ReplaceAll(line, "JSONRPCMessage\n", "")
				if strings.TrimSpace(line) != "" {
					filtered = append(filtered, line)
				}
			}
			errObj["message"] = strings.Join(filtered, "\n")
		}
		rpcResp["error"] = errObj
	}

	result, err := json.Marshal(rpcResp)
	if err != nil {
		return []byte(`{"error":"Request validation failed"}`)
	}
	return result
}

// StatusWriter captures the status code
func (w *responseWriter) WriteHeader(code int) {
	w.ResponseWriter.WriteHeader(code)
}

func (w *responseWriter) Status() int {
	return w.ResponseWriter.Status()
}

// Flush implements http.Flusher
func (w *responseWriter) Flush() {
	if f, ok := w.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}
