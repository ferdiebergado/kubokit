package config

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"

	"github.com/ferdiebergado/kubokit/internal/pkg/env"
	timex "github.com/ferdiebergado/kubokit/internal/pkg/time"
)

const maskChar = "*"

type App struct {
	Env       string `json:"env,omitempty" env:"ENV"`
	Key       string `json:"key,omitempty" env:"KEY"`
	URL       string `json:"url,omitempty" env:"URL"`
	LogLevel  string `json:"log_level,omitempty" env:"LOG_LEVEL"`
	ClientURL string `json:"client_url,omitempty" env:"CLIENT_URL"`
}

func (a *App) LogValue() slog.Value {
	return slog.GroupValue(
		slog.String("env", a.Env),
		slog.String("key", maskChar),
		slog.String("url", a.URL),
		slog.String("log_level", a.LogLevel),
	)
}

type Server struct {
	Port            int            `json:"port,omitempty" env:"PORT"`
	ReadTimeout     timex.Duration `json:"read_timeout,omitempty"`
	WriteTimeout    timex.Duration `json:"write_timeout,omitempty"`
	IdleTimeout     timex.Duration `json:"idle_timeout,omitempty"`
	ShutdownTimeout timex.Duration `json:"shutdown_timeout,omitempty"`
	MaxBodyBytes    int64          `json:"max_body_bytes,omitempty"`
}

type DB struct {
	Host    string `json:"host,omitempty" env:"DB_HOST"`
	Port    int    `json:"port,omitempty" env:"DB_PORT"`
	User    string `json:"user,omitempty" env:"DB_USER"`
	Pass    string `json:"pass,omitempty" env:"DB_PASS"`
	Name    string `json:"name,omitempty" env:"DB_NAME"`
	SSLMode string `json:"ssl_mode,omitempty" env:"DB_SSLMODE"`

	Driver          string         `json:"driver,omitempty"`
	MaxOpenConns    int            `json:"max_open_conns,omitempty"`
	MaxIdleConns    int            `json:"max_idle_conns,omitempty"`
	ConnMaxIdleTime timex.Duration `json:"conn_max_idle_time,omitempty"`
	ConnMaxLifetime timex.Duration `json:"conn_max_lifetime,omitempty"`
	PingTimeout     timex.Duration `json:"ping_timeout,omitempty"`
}

func (d *DB) LogValue() slog.Value {
	return slog.GroupValue(
		slog.String("host", d.Host),
		slog.Int("port", d.Port),
		slog.String("user", d.User),
		slog.String("pass", maskChar),
		slog.String("name", d.Name),
		slog.String("ssl_mode", d.SSLMode),
		slog.String("driver", d.Driver),
		slog.Int("max_open_conns", d.MaxOpenConns),
		slog.Int("max_idle_conns", d.MaxIdleConns),
		slog.Duration("conn_max_idle", d.ConnMaxIdleTime.Duration),
		slog.Duration("conn_max_lifetime", d.ConnMaxLifetime.Duration),
		slog.Duration("ping_timeout", d.PingTimeout.Duration),
	)
}

type JWT struct {
	JTILength  uint32         `json:"jti_length,omitempty"`
	Issuer     string         `json:"issuer,omitempty"`
	TTL        timex.Duration `json:"ttl,omitempty"`
	RefreshTTL timex.Duration `json:"refresh_ttl,omitempty"`
}

type Email struct {
	Templates string         `json:"templates,omitempty"`
	Layout    string         `json:"layout,omitempty"`
	Sender    string         `json:"sender,omitempty"`
	VerifyTTL timex.Duration `json:"verify_ttl,omitempty"`
}

type SMTP struct {
	Host     string `json:"host,omitempty" env:"SMTP_HOST"`
	Port     int    `json:"port,omitempty" env:"SMTP_PORT"`
	User     string `json:"user,omitempty" env:"SMTP_USER"`
	Password string `json:"password,omitempty" env:"SMTP_PASS"`
}

func (s *SMTP) LogValue() slog.Value {
	return slog.GroupValue(
		slog.String("host", s.Host),
		slog.Int("port", s.Port),
		slog.String("user", s.User),
		slog.String("pass", maskChar),
	)
}

type Argon2 struct {
	Memory     uint32 `json:"memory,omitempty"`
	Iterations uint32 `json:"iterations,omitempty"`
	Threads    uint8  `json:"threads,omitempty"`
	SaltLength uint32 `json:"salt_length,omitempty"`
	KeyLength  uint32 `json:"key_length,omitempty"`
}

type CORS struct {
	AllowedOrigin    string   `json:"allowed_origin,omitempty" env:"CLIENT_URL"`
	AllowedMethods   []string `json:"allowed_methods,omitempty"`
	AllowedHeaders   []string `json:"allowed_headers,omitempty"`
	AllowCredentials string   `json:"allow_credentials,omitempty"`
}

type Cookie struct {
	Name string `json:"name,omitempty"`
}

type Config struct {
	*App    `json:"app,omitempty"`
	*Server `json:"server,omitempty"`
	*DB     `json:"db,omitempty"`
	*JWT    `json:"jwt,omitempty"`
	*SMTP   `json:"smtp,omitempty"`
	*Email  `json:"email,omitempty"`
	*Argon2 `json:"argon2,omitempty"`
	*CORS   `json:"cors,omitempty"`
	*Cookie `json:"cookie,omitempty"`
}

func (c *Config) LogValue() slog.Value {
	return slog.GroupValue(
		slog.Any("app", c.App),
		slog.Any("server", c.Server),
		slog.Any("db", c.DB),
		slog.Any("jwt", c.JWT),
		slog.Any("smtp", c.SMTP),
		slog.Any("email", c.Email),
		slog.Any("argon2", c.Argon2),
		slog.Any("cors", c.CORS),
		slog.Any("cookie", c.Cookie),
	)
}

func Load(cfgFile string) (*Config, error) {
	slog.Info("Loading config...")
	cfg, err := parseCfgFile(cfgFile)
	if err != nil {
		return nil, fmt.Errorf("parse config file %q: %w", cfgFile, err)
	}

	if err := env.OverrideStruct(cfg); err != nil {
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
