package server

import (
	"context"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/risedphantom/mcp-oauth2-proxy/internal/config"
	"github.com/risedphantom/mcp-oauth2-proxy/internal/middleware"
	oauth2facade "github.com/risedphantom/mcp-oauth2-proxy/internal/oauth2"
	"github.com/risedphantom/mcp-oauth2-proxy/internal/proxy"
	log "github.com/sirupsen/logrus"
)

// Run starts the HTTP server with the given configuration.
func Run(cfg *config.Config) error {
	ctx := context.Background()

	// Create reverse proxy (header mutations applied inside Rewrite)
	rp, err := proxy.NewProxy(cfg.Upstream, cfg.Headers)
	if err != nil {
		return err
	}

	// Discover Keycloak endpoints for OAuth2 AS facade
	kcEndpoints, err := oauth2facade.DiscoverKeycloak(ctx, cfg.Auth.IssuerURL)
	if err != nil {
		return err
	}

	// Create JWT validator (fetches + caches JWKS from Keycloak)
	jwtValidator, err := oauth2facade.NewJWTValidator(ctx, kcEndpoints.JwksURI)
	if err != nil {
		return err
	}

	// Wrap with auth middleware (JWT signature + expiration validation)
	handler := middleware.NewAuthMiddleware(rp, cfg.Auth, jwtValidator)

	// Create OAuth2 store and handlers
	oauth2Store := oauth2facade.NewStore(cfg.Auth.ClientTTL, cfg.Auth.SessionTTL, cfg.Auth.CodeTTL)
	defer oauth2Store.Close()

	oauth2Handlers := oauth2facade.NewHandlers(
		oauth2Store,
		kcEndpoints,
		cfg.Auth.BaseURL,
		cfg.Auth.ClientID,
		cfg.Auth.ClientSecret,
		cfg.Auth.ScopesSupported,
		cfg.Auth.OIDCScopes,
		cfg.Auth.AuthorizationServers,
	)

	// Set up routes
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("ok")) //nolint:errcheck
	})
	mux.HandleFunc("/readyz", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("ok")) //nolint:errcheck
	})
	mux.Handle("/.well-known/oauth-protected-resource", oauth2Handlers.HandleResourceMetadata())
	mux.Handle("/.well-known/oauth-authorization-server", oauth2Handlers.HandleASMetadata())
	mux.Handle("/.well-known/oauth-authorization-server/", oauth2Handlers.HandleASMetadata())
	mux.Handle("/.well-known/openid-configuration", oauth2Handlers.HandleASMetadata())
	mux.Handle("/.well-known/openid-configuration/", oauth2Handlers.HandleASMetadata())
	mux.Handle("/oauth/register", oauth2Handlers.HandleRegister())
	mux.Handle("/oauth/authorize", oauth2Handlers.HandleAuthorize())
	mux.Handle("/oauth/callback", oauth2Handlers.HandleCallback())
	mux.Handle("/oauth/token", oauth2Handlers.HandleToken())
	mux.Handle("/", handler)

	srv := &http.Server{
		Addr:         cfg.Server.ListenAddress,
		Handler:      middleware.NewLoggingMiddleware(mux, "/healthz", "/readyz"),
		ReadTimeout:  cfg.Server.ReadTimeout,
		WriteTimeout: cfg.Server.WriteTimeout,
		IdleTimeout:  cfg.Server.IdleTimeout,
	}

	// Graceful shutdown
	errCh := make(chan error, 1)
	go func() {
		log.WithField("address", cfg.Server.ListenAddress).Info("Starting server")
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			errCh <- err
		}
		close(errCh)
	}()

	// Wait for interrupt signal
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)

	select {
	case sig := <-quit:
		log.WithField("signal", sig.String()).Info("Shutting down server")
	case err := <-errCh:
		if err != nil {
			return err
		}
	}

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	if err := srv.Shutdown(shutdownCtx); err != nil {
		log.WithError(err).Error("Server forced to shutdown")
		return err
	}

	log.Info("Server stopped gracefully")
	return nil
}
