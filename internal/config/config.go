package config

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strconv"

	timex "github.com/ferdiebergado/kubokit/internal/pkg/time"
)

type Server struct {
	URL             string         `json:"url,omitempty"`
	Port            int            `json:"port,omitempty"`
	ReadTimeout     timex.Duration `json:"read_timeout,omitempty"`
	WriteTimeout    timex.Duration `json:"write_timeout,omitempty"`
	IdleTimeout     timex.Duration `json:"idle_timeout,omitempty"`
	ShutdownTimeout timex.Duration `json:"shutdown_timeout,omitempty"`
	MaxBodyBytes    int64          `json:"max_body_bytes,omitempty"`
}

type DB struct {
	Driver          string         `json:"driver,omitempty"`
	MaxOpenConns    int            `json:"max_open_conns,omitempty"`
	MaxIdleConns    int            `json:"max_idle_conns,omitempty"`
	ConnMaxIdleTime timex.Duration `json:"conn_max_idle_time,omitempty"`
	ConnMaxLifetime timex.Duration `json:"conn_max_lifetime,omitempty"`
	PingTimeout     timex.Duration `json:"ping_timeout,omitempty"`
}

type JWT struct {
	JTILength  uint32         `json:"jti_length,omitempty"`
	Issuer     string         `json:"issuer,omitempty"`
	TTL        timex.Duration `json:"ttl,omitempty"`
	RefreshTTL timex.Duration `json:"refresh_ttl,omitempty"`
}

type Cookie struct {
	Name   string         `json:"name,omitempty"`
	MaxAge timex.Duration `json:"max_age,omitempty"`
}

type Email struct {
	Templates string         `json:"templates,omitempty"`
	Layout    string         `json:"layout,omitempty"`
	Sender    string         `json:"sender,omitempty"`
	VerifyTTL timex.Duration `json:"verify_ttl,omitempty"`
}

type Argon2 struct {
	Memory     uint32 `json:"memory,omitempty"`
	Iterations uint32 `json:"iterations,omitempty"`
	Threads    uint8  `json:"threads,omitempty"`
	SaltLength uint32 `json:"salt_length,omitempty"`
	KeyLength  uint32 `json:"key_length,omitempty"`
}

type CSRF struct {
	HeaderName  string `json:"header_name,omitempty"`
	CookieName  string `json:"cookie_name,omitempty"`
	TokenLength uint32 `json:"token_length,omitempty"`
}

type Config struct {
	*Server `json:"server,omitempty"`
	*DB     `json:"db,omitempty"`
	*JWT    `json:"jwt,omitempty"`
	*Cookie `json:"cookie,omitempty"`
	*Email  `json:"email,omitempty"`
	*Argon2 `json:"argon2,omitempty"`
	*CSRF   `json:"csrf,omitempty"`
}

func (o *Config) LogValue() slog.Value {
	return slog.GroupValue(
		slog.Any("server", o.Server),
		slog.Any("db", o.DB),
		slog.Any("jwt", o.JWT),
		slog.Any("cookie", o.Cookie),
		slog.Any("email", o.Email),
		slog.Any("argon2", o.Argon2),
		slog.Any("csrf", o.CSRF),
	)
}

func Load(cfgFile string) (*Config, error) {
	slog.Info("Loading config...")
	cfg, err := parseCfgFile(cfgFile)
	if err != nil {
		return nil, fmt.Errorf("parse config file %q: %w", cfgFile, err)
	}

	if err := overrideWithEnv(cfg); err != nil {
		return nil, fmt.Errorf("override with env: %w", err)
	}

	slog.Info("Config loaded.", "config_file", cfgFile, slog.Any("config", cfg))
	return cfg, nil
}

func parseCfgFile(cfgFile string) (*Config, error) {
	cfgFile = filepath.Clean(cfgFile)
	configFile, err := os.ReadFile(cfgFile)
	if err != nil {
		return nil, fmt.Errorf("read config file %s: %w", cfgFile, err)
	}

	var cfg Config
	if err := json.Unmarshal(configFile, &cfg); err != nil {
		return nil, fmt.Errorf("decode json config %s: %w", configFile, err)
	}

	return &cfg, nil
}

func overrideWithEnv(cfg *Config) error {
	if url, ok := os.LookupEnv("URL"); ok {
		cfg.Server.URL = url
	}

	if portStr, ok := os.LookupEnv("PORT"); ok {
		port, err := strconv.Atoi(portStr)
		if err != nil {
			return fmt.Errorf("convert port string %q to integer: %w", portStr, err)
		}
		cfg.Server.Port = port
	}
	return nil
}
