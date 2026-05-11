package cmd

import (
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/sbomit/sbomit/pkg/generator"
	"github.com/spf13/cobra"
)

var serverPort  string
var serverToken string

var ServerCmd = &cobra.Command{
	Use:   "server",
	Short: "Start the SBOMit HTTP server",
	Long: `Start the SBOMit HTTP server.

Endpoints:
  POST /generate   — accepts a witness attestation JSON, returns SPDX 2.3 SBOM
  GET  /health     — health check

Authentication (in order of precedence):
  1. GitHub OIDC   — X-GitHub-OIDC-Token header (no secrets needed)
  2. Bearer token  — Authorization: Bearer <token>
  3. Open          — if SBOMIT_TOKEN unset, all requests allowed

Environment variables:
  SBOMIT_TOKEN   static bearer token fallback (optional)
  SBOMIT_PORT    port to listen on (default: 5000)`,
	RunE: func(cmd *cobra.Command, args []string) error {
		if serverToken == "" {
			serverToken = os.Getenv("SBOMIT_TOKEN")
		}
		if serverPort == "" {
			serverPort = os.Getenv("SBOMIT_PORT")
		}
		if serverPort == "" {
			serverPort = "5000"
		}

		mux := http.NewServeMux()
		mux.HandleFunc("/generate", authMiddleware(handleGenerate))
		mux.HandleFunc("/health",   handleHealth)

		addr := ":" + serverPort
		fmt.Fprintf(os.Stderr, "SBOMit server listening on %s\n", addr)
		fmt.Fprintf(os.Stderr, "Auth: GitHub OIDC enabled")
		if serverToken != "" {
			fmt.Fprintf(os.Stderr, " + bearer token fallback\n")
		} else {
			fmt.Fprintf(os.Stderr, "\n")
		}
		return http.ListenAndServe(addr, mux)
	},
}

func init() {
	ServerCmd.Flags().StringVarP(&serverPort, "port", "p", "", "Port (default: 5000)")
	ServerCmd.Flags().StringVarP(&serverToken, "token", "t", "", "Static bearer token fallback")
}

// ── Auth middleware ───────────────────────────────────────────────────────────

func authMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// No auth configured — open access
		if serverToken == "" {
			// Still try OIDC to enrich logging, but don't require it
			if oidcToken := r.Header.Get("X-GitHub-OIDC-Token"); oidcToken != "" {
				if claims, err := verifyGitHubOIDC(oidcToken); err == nil {
					fmt.Fprintf(os.Stderr, "OIDC: repo=%s ref=%s sha=%s\n",
						claims.Repository, claims.Ref, claims.SHA[:8])
					r.Header.Set("X-SBOMit-Repo", claims.Repository)
					r.Header.Set("X-SBOMit-SHA",  claims.SHA)
				}
			}
			next(w, r)
			return
		}

		// Try GitHub OIDC first
		if oidcToken := r.Header.Get("X-GitHub-OIDC-Token"); oidcToken != "" {
			claims, err := verifyGitHubOIDC(oidcToken)
			if err != nil {
				jsonError(w, "invalid OIDC token: "+err.Error(), http.StatusUnauthorized)
				return
			}
			fmt.Fprintf(os.Stderr, "OIDC auth: repo=%s ref=%s sha=%s\n",
				claims.Repository, claims.Ref, claims.SHA[:8])
			r.Header.Set("X-SBOMit-Repo", claims.Repository)
			r.Header.Set("X-SBOMit-SHA",  claims.SHA)
			next(w, r)
			return
		}

		// Fall back to bearer token
		auth := r.Header.Get("Authorization")
		if strings.HasPrefix(auth, "Bearer ") &&
			strings.TrimPrefix(auth, "Bearer ") == serverToken {
			next(w, r)
			return
		}

		jsonError(w, "unauthorized: provide X-GitHub-OIDC-Token or Bearer token",
			http.StatusUnauthorized)
	}
}

// ── OIDC verification ─────────────────────────────────────────────────────────

const githubOIDCIssuer = "https://token.actions.githubusercontent.com"
const githubJWKSURL    = "https://token.actions.githubusercontent.com/.well-known/jwks"

type jwks struct {
	Keys []jwk `json:"keys"`
}

type jwk struct {
	Kid string `json:"kid"`
	Kty string `json:"kty"`
	Alg string `json:"alg"`
	N   string `json:"n"`
	E   string `json:"e"`
}

type oidcClaims struct {
	Issuer          string `json:"iss"`
	ExpiresAt       int64  `json:"exp"`
	Repository      string `json:"repository"`
	RepositoryOwner string `json:"repository_owner"`
	Ref             string `json:"ref"`
	SHA             string `json:"sha"`
	Workflow        string `json:"workflow"`
	Actor           string `json:"actor"`
	RunID           string `json:"run_id"`
}

func verifyGitHubOIDC(token string) (*oidcClaims, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, fmt.Errorf("invalid JWT")
	}

	// Decode header
	hdrBytes, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return nil, fmt.Errorf("decode header: %w", err)
	}
	var header struct {
		Kid string `json:"kid"`
		Alg string `json:"alg"`
	}
	if err := json.Unmarshal(hdrBytes, &header); err != nil {
		return nil, fmt.Errorf("parse header: %w", err)
	}
	if header.Alg != "RS256" {
		return nil, fmt.Errorf("unsupported alg: %s", header.Alg)
	}

	// Fetch JWKS and find key
	resp, err := http.Get(githubJWKSURL)
	if err != nil {
		return nil, fmt.Errorf("fetch JWKS: %w", err)
	}
	defer resp.Body.Close()
	var keys jwks
	if err := json.NewDecoder(resp.Body).Decode(&keys); err != nil {
		return nil, fmt.Errorf("decode JWKS: %w", err)
	}

	var matchedKey *jwk
	for i := range keys.Keys {
		if keys.Keys[i].Kid == header.Kid {
			matchedKey = &keys.Keys[i]
			break
		}
	}
	if matchedKey == nil {
		return nil, fmt.Errorf("no key for kid=%s", header.Kid)
	}

	// Build RSA public key
	nBytes, err := base64.RawURLEncoding.DecodeString(matchedKey.N)
	if err != nil {
		return nil, fmt.Errorf("decode N: %w", err)
	}
	eBytes, err := base64.RawURLEncoding.DecodeString(matchedKey.E)
	if err != nil {
		return nil, fmt.Errorf("decode E: %w", err)
	}
	e := 0
	for _, b := range eBytes {
		e = e<<8 | int(b)
	}
	pubKey := &rsa.PublicKey{
		N: new(big.Int).SetBytes(nBytes),
		E: e,
	}

	// Verify signature
	signingInput := parts[0] + "." + parts[1]
	h := sha256.Sum256([]byte(signingInput))
	sigBytes, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return nil, fmt.Errorf("decode sig: %w", err)
	}
	if err := rsa.VerifyPKCS1v15(pubKey, crypto.SHA256, h[:], sigBytes); err != nil {
		return nil, fmt.Errorf("invalid signature: %w", err)
	}

	// Parse and validate claims
	payloadBytes, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, fmt.Errorf("decode payload: %w", err)
	}
	var claims oidcClaims
	if err := json.Unmarshal(payloadBytes, &claims); err != nil {
		return nil, fmt.Errorf("parse claims: %w", err)
	}
	if claims.Issuer != githubOIDCIssuer {
		return nil, fmt.Errorf("invalid issuer: %s", claims.Issuer)
	}
	if time.Now().Unix() > claims.ExpiresAt {
		return nil, fmt.Errorf("token expired")
	}

	return &claims, nil
}

// ── Handlers ──────────────────────────────────────────────────────────────────

func handleHealth(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"status": "ok",
		"time":   time.Now().UTC().Format(time.RFC3339),
	})
}

func handleGenerate(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		jsonError(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	format  := r.URL.Query().Get("format")
	if format == "" { format = "spdx23" }

	docName := r.URL.Query().Get("name")
	if docName == "" {
		// Use repo name from OIDC if available
		docName = r.Header.Get("X-SBOMit-Repo")
		if docName == "" { docName = "sbomit-generated-sbom" }
		// Strip org prefix (org/repo → repo)
		if idx := strings.LastIndex(docName, "/"); idx >= 0 {
			docName = docName[idx+1:]
		}
	}

	body, err := io.ReadAll(io.LimitReader(r.Body, 200<<20))
	if err != nil || len(body) == 0 {
		jsonError(w, "failed to read body", http.StatusBadRequest)
		return
	}
	defer r.Body.Close()

	tmpIn, err := os.CreateTemp("", "sbomit-att-*.json")
	if err != nil {
		jsonError(w, "temp file error: "+err.Error(), http.StatusInternalServerError)
		return
	}
	defer os.Remove(tmpIn.Name())
	tmpIn.Write(body)
	tmpIn.Close()

	tmpOut, err := os.CreateTemp("", "sbomit-sbom-*.json")
	if err != nil {
		jsonError(w, "temp file error: "+err.Error(), http.StatusInternalServerError)
		return
	}
	defer os.Remove(tmpOut.Name())
	tmpOut.Close()

	opts := &generator.Options{
		DocumentName:     docName,
		DocumentVersion:  "0.0.1",
		AttestationTypes: []string{"material", "command-run", "product", "network-trace"},
		OutputFormat:     format,
		OutputPath:       tmpOut.Name(),
	}

	if err := generator.New(opts).GenerateFromFile(tmpIn.Name()); err != nil {
		jsonError(w, "generation failed: "+err.Error(), http.StatusInternalServerError)
		return
	}

	sbomBytes, err := os.ReadFile(tmpOut.Name())
	if err != nil {
		jsonError(w, "read output failed: "+err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Content-Disposition",
		fmt.Sprintf(`attachment; filename="%s.spdx.json"`, docName))
	w.WriteHeader(http.StatusOK)
	w.Write(sbomBytes)
}

func jsonError(w http.ResponseWriter, msg string, code int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(map[string]string{"error": msg})
}
