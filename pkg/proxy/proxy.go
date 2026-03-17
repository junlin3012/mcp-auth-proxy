package proxy

import (
	"crypto/rsa"
	"fmt"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
)

type ProxyRouter struct {
	externalURL       string
	proxy             http.Handler
	publicKey         *rsa.PublicKey
	proxyHeaders      http.Header
	httpStreamingOnly bool
}

func NewProxyRouter(
	externalURL string,
	proxy http.Handler,
	publicKey *rsa.PublicKey,
	proxyHeaders http.Header,
	httpStreamingOnly bool,
) (*ProxyRouter, error) {
	return &ProxyRouter{
		externalURL:       externalURL,
		proxy:             proxy,
		publicKey:         publicKey,
		proxyHeaders:      proxyHeaders,
		httpStreamingOnly: httpStreamingOnly,
	}, nil
}

const (
	OauthProtectedResourceEndpoint = "/.well-known/oauth-protected-resource"
)

func (p *ProxyRouter) SetupRoutes(router gin.IRouter) {
	router.GET(OauthProtectedResourceEndpoint, p.handleProtectedResource)
	router.Use(p.handleProxy)
}

type protectedResourceResponse struct {
	Resource             string   `json:"resource"`
	AuthorizationServers []string `json:"authorization_servers"`
}

func (p *ProxyRouter) handleProtectedResource(c *gin.Context) {
	c.JSON(http.StatusOK, protectedResourceResponse{
		Resource:             p.externalURL,
		AuthorizationServers: []string{p.externalURL},
	})
}

func (p *ProxyRouter) handleProxy(c *gin.Context) {
	// Defense-in-depth: strip identity header from incoming requests to prevent spoofing.
	// Only auth-proxy should set this header, never external clients.
	c.Request.Header.Del("X-Authenticated-User")

	authHeader := c.Request.Header.Get("Authorization")
	if !strings.HasPrefix(authHeader, "Bearer ") {
		c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized"})
		return
	}
	bearerToken := strings.TrimPrefix(authHeader, "Bearer ")

	token, err := jwt.Parse(bearerToken, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return p.publicKey, nil
	})

	if err != nil || !token.Valid {
		c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "Invalid token"})
		return
	}

	// Extract user identity from validated JWT and forward to upstream.
	// ContextForge consumes this via TRUST_PROXY_AUTH + PROXY_USER_HEADER.
	if claims, ok := token.Claims.(jwt.MapClaims); ok {
		if sub, ok := claims["sub"].(string); ok && sub != "" {
			c.Request.Header.Set("X-Authenticated-User", sub)
		} else if clientID, ok := claims["client_id"].(string); ok && clientID != "" {
			c.Request.Header.Set("X-Authenticated-User", clientID)
		}
	}

	if p.httpStreamingOnly && isSSEGetRequest(c.Request) {
		c.AbortWithStatusJSON(http.StatusMethodNotAllowed, gin.H{"error": "SSE (GET) streaming is not supported by this backend; use POST-based HTTP streaming instead"})
		return
	}

	c.Request.Header.Del("Authorization")
	for key, values := range p.proxyHeaders {
		// Never allow static proxy-headers to override the validated identity header.
		if strings.EqualFold(key, "X-Authenticated-User") {
			continue
		}
		for _, value := range values {
			c.Request.Header.Add(key, value)
		}
	}

	p.proxy.ServeHTTP(c.Writer, c.Request)
}

func isSSEGetRequest(r *http.Request) bool {
	if r.Method != http.MethodGet {
		return false
	}
	accept := r.Header.Get("Accept")
	if accept == "" {
		return false
	}
	for _, value := range strings.Split(accept, ",") {
		mediaType := strings.TrimSpace(strings.ToLower(value))
		if idx := strings.Index(mediaType, ";"); idx != -1 {
			mediaType = strings.TrimSpace(mediaType[:idx])
		}
		if mediaType == "text/event-stream" {
			return true
		}
	}
	return false
}
