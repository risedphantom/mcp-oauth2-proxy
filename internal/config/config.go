package config

import (
	"fmt"
	"net/url"
	"time"

	"github.com/spf13/viper"
)

// Config is the top-level configuration structure.
type Config struct {
	Server   ServerConfig   `mapstructure:"server"`
	Upstream UpstreamConfig `mapstructure:"upstream"`
	Headers  HeadersConfig  `mapstructure:"headers"`
	Auth     AuthConfig     `mapstructure:"auth"`
}

// AuthConfig holds MCP Authorization, OAuth2 AS facade, and OIDC client credentials settings.
// Auth is active when BaseURL is set; when omitted the proxy accepts unauthenticated requests.
type AuthConfig struct {
	BaseURL              string        `mapstructure:"baseUrl"`
	AuthorizationServers []string      `mapstructure:"authorizationServers"`
	ScopesSupported      []string      `mapstructure:"scopesSupported"`
	OIDCScopes           []string      `mapstructure:"oidcScopes"` // scopes to request from Keycloak, defaults to scopesSupported if empty
	ClientTTL            time.Duration `mapstructure:"clientTtl"`
	SessionTTL           time.Duration `mapstructure:"sessionTtl"`
	CodeTTL              time.Duration `mapstructure:"codeTtl"`
	IssuerURL            string        `mapstructure:"issuerUrl"`
	ClientID             string        `mapstructure:"clientId"`
	ClientSecret         string        `mapstructure:"clientSecret"`
}

// ServerConfig holds HTTP server settings.
type ServerConfig struct {
	ListenAddress string        `mapstructure:"listenAddress"`
	ReadTimeout   time.Duration `mapstructure:"readTimeout"`
	WriteTimeout  time.Duration `mapstructure:"writeTimeout"`
	IdleTimeout   time.Duration `mapstructure:"idleTimeout"`
}

// UpstreamConfig holds the upstream MCP server URL.
type UpstreamConfig struct {
	URL string `mapstructure:"url"`
}

// MutationAction defines the type of header mutation to perform.
type MutationAction string

const (
	MutationActionRemove        MutationAction = "remove"
	MutationActionAdd           MutationAction = "add"
	MutationActionSetXForwarded MutationAction = "set-x-forwarded"
)

// ValueFrom specifies a dynamic source for a header value.
type ValueFrom struct {
	RequestHeader       string `mapstructure:"requestHeader"`
	QueryParameter      string `mapstructure:"queryParameter"`
	AuthorizationHeader bool   `mapstructure:"authorizationHeader"`
}

// HeaderMutation defines a single ordered header mutation.
type HeaderMutation struct {
	Action    MutationAction `mapstructure:"action"`
	Name      string         `mapstructure:"name"`
	Value     string         `mapstructure:"value"`
	ValueFrom *ValueFrom     `mapstructure:"valueFrom"`
}

// HeadersConfig controls header mutation on proxied requests.
type HeadersConfig struct {
	Mutations []HeaderMutation `mapstructure:"mutations"`
}

// setDefaults configures viper defaults.
func setDefaults() {
	viper.SetDefault("server.listenAddress", ":8080")
	viper.SetDefault("server.readTimeout", 30*time.Second)
	viper.SetDefault("server.writeTimeout", 0)
	viper.SetDefault("server.idleTimeout", 120*time.Second)

	viper.SetDefault("auth.clientTtl", 24*time.Hour)
	viper.SetDefault("auth.sessionTtl", 10*time.Minute)
	viper.SetDefault("auth.codeTtl", 5*time.Minute)

	// Bind env vars for fields that don't have defaults but should be
	// overridable via environment (e.g. MCP_OAUTH2_PROXY_AUTH_CLIENTSECRET).
	_ = viper.BindEnv("upstream.url")
	_ = viper.BindEnv("auth.baseUrl")
	_ = viper.BindEnv("auth.issuerUrl")
	_ = viper.BindEnv("auth.clientId")
	_ = viper.BindEnv("auth.clientSecret")
}

// Load reads configuration from the given YAML file path and returns a Config.
func Load(path string) (*Config, error) {
	setDefaults()

	viper.SetConfigFile(path)
	if err := viper.ReadInConfig(); err != nil {
		return nil, fmt.Errorf("reading config file: %w", err)
	}

	var cfg Config
	if err := viper.Unmarshal(&cfg); err != nil {
		return nil, fmt.Errorf("unmarshalling config: %w", err)
	}

	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("validating config: %w", err)
	}

	if len(cfg.Auth.AuthorizationServers) == 0 {
		cfg.Auth.AuthorizationServers = []string{cfg.Auth.BaseURL}
	}

	return &cfg, nil
}

// Validate checks that all required configuration fields are set.
func (c *Config) Validate() error {
	if c.Upstream.URL == "" {
		return fmt.Errorf("upstream.url is required")
	}
	u, err := url.Parse(c.Upstream.URL)
	if err != nil {
		return fmt.Errorf("upstream.url is not a valid URL: %w", err)
	}
	if u.Scheme == "" || u.Host == "" {
		return fmt.Errorf("upstream.url must be an absolute URL with scheme and host")
	}
	if err := c.validateHeaders(); err != nil {
		return err
	}
	if err := c.validateAuth(); err != nil {
		return err
	}
	return nil
}

// validateAuth checks that auth and OIDC configuration is well-formed.
func (c *Config) validateAuth() error {
	if c.Auth.IssuerURL == "" {
		return fmt.Errorf("auth.issuerUrl is required")
	}
	if c.Auth.ClientID == "" {
		return fmt.Errorf("auth.clientId is required")
	}
	if c.Auth.ClientSecret == "" {
		return fmt.Errorf("auth.clientSecret is required")
	}
	if c.Auth.BaseURL == "" {
		return fmt.Errorf("auth.baseUrl is required")
	}
	u, err := url.Parse(c.Auth.BaseURL)
	if err != nil {
		return fmt.Errorf("auth.baseUrl is not a valid URL: %w", err)
	}
	if u.Scheme == "" || u.Host == "" {
		return fmt.Errorf("auth.baseUrl must be an absolute URL with scheme and host")
	}
	if u.Fragment != "" {
		return fmt.Errorf("auth.baseUrl must not contain a fragment")
	}

	if len(c.Auth.AuthorizationServers) > 0 {
		for i, as := range c.Auth.AuthorizationServers {
			u, err := url.Parse(as)
			if err != nil {
				return fmt.Errorf("auth.authorizationServers[%d] is not a valid URL: %w", i, err)
			}
			if u.Scheme == "" || u.Host == "" {
				return fmt.Errorf("auth.authorizationServers[%d] must be an absolute URL with scheme and host", i)
			}
		}
	}

	return nil
}

// validateHeaders checks that all header mutations are well-formed.
func (c *Config) validateHeaders() error {
	for i, m := range c.Headers.Mutations {
		switch m.Action {
		case MutationActionRemove:
			if m.Name == "" {
				return fmt.Errorf("headers.mutations[%d]: remove action requires 'name'", i)
			}
			if m.Value != "" || m.ValueFrom != nil {
				return fmt.Errorf("headers.mutations[%d]: remove action must not have 'value' or 'valueFrom'", i)
			}
		case MutationActionAdd:
			if m.Name == "" {
				return fmt.Errorf("headers.mutations[%d]: add action requires 'name'", i)
			}
			hasValue := m.Value != ""
			hasValueFrom := m.ValueFrom != nil
			if !hasValue && !hasValueFrom {
				return fmt.Errorf("headers.mutations[%d]: add action requires either 'value' or 'valueFrom'", i)
			}
			if hasValue && hasValueFrom {
				return fmt.Errorf("headers.mutations[%d]: add action must not have both 'value' and 'valueFrom'", i)
			}
			if hasValueFrom {
				sources := 0
				if m.ValueFrom.RequestHeader != "" {
					sources++
				}
				if m.ValueFrom.QueryParameter != "" {
					sources++
				}
				if m.ValueFrom.AuthorizationHeader {
					sources++
				}
				if sources != 1 {
					return fmt.Errorf("headers.mutations[%d]: valueFrom must have exactly one source (requestHeader or queryParameter)", i)
				}
			}
		case MutationActionSetXForwarded:
			if m.Name != "" || m.Value != "" || m.ValueFrom != nil {
				return fmt.Errorf("headers.mutations[%d]: set-x-forwarded action must not have 'name', 'value' or 'valueFrom'", i)
			}
		default:
			return fmt.Errorf("headers.mutations[%d]: invalid action %q", i, m.Action)
		}
	}
	return nil
}
