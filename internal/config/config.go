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

type ServerOptions struct {
	URL             string         `json:"url,omitempty"`
	Port            int            `json:"port,omitempty"`
	ReadTimeout     timex.Duration `json:"read_timeout,omitempty"`
	WriteTimeout    timex.Duration `json:"write_timeout,omitempty"`
	IdleTimeout     timex.Duration `json:"idle_timeout,omitempty"`
	ShutdownTimeout timex.Duration `json:"shutdown_timeout,omitempty"`
	MaxBodyBytes    int64          `json:"max_body_bytes,omitempty"`
}

type DBOptions struct {
	Driver          string         `json:"driver,omitempty"`
	MaxOpenConns    int            `json:"max_open_conns,omitempty"`
	MaxIdleConns    int            `json:"max_idle_conns,omitempty"`
	ConnMaxIdleTime timex.Duration `json:"conn_max_idle_time,omitempty"`
	ConnMaxLifetime timex.Duration `json:"conn_max_lifetime,omitempty"`
	PingTimeout     timex.Duration `json:"ping_timeout,omitempty"`
}

type JWTOptions struct {
	JTILength  uint32         `json:"jti_length,omitempty"`
	Issuer     string         `json:"issuer,omitempty"`
	TTL        timex.Duration `json:"ttl,omitempty"`
	RefreshTTL timex.Duration `json:"refresh_ttl,omitempty"`
}

type CookieOptions struct {
	Name   string         `json:"name,omitempty"`
	MaxAge timex.Duration `json:"max_age,omitempty"`
}

type EmailOptions struct {
	Templates string         `json:"templates,omitempty"`
	Layout    string         `json:"layout,omitempty"`
	Sender    string         `json:"sender,omitempty"`
	VerifyTTL timex.Duration `json:"verify_ttl,omitempty"`
}

type Argon2Options struct {
	Memory     uint32 `json:"memory,omitempty"`
	Iterations uint32 `json:"iterations,omitempty"`
	Threads    uint8  `json:"threads,omitempty"`
	SaltLength uint32 `json:"salt_length,omitempty"`
	KeyLength  uint32 `json:"key_length,omitempty"`
}

type Options struct {
	Server *ServerOptions `json:"server,omitempty"`
	DB     *DBOptions     `json:"db,omitempty"`
	JWT    *JWTOptions    `json:"jwt,omitempty"`
	Cookie *CookieOptions `json:"cookie,omitempty"`
	Email  *EmailOptions  `json:"email,omitempty"`
	Argon2 *Argon2Options `json:"argon2,omitempty"`
}

func (o *Options) LogValue() slog.Value {
	return slog.GroupValue(
		slog.Any("server", o.Server),
		slog.Any("db", o.DB),
		slog.Any("jwt", o.JWT),
		slog.Any("cookie", o.Cookie),
		slog.Any("email", o.Email),
		slog.Any("argon2", o.Argon2),
	)
}

func New(cfgFile string) (*Options, error) {
	slog.Info("Loading config...")
	opts, err := parseCfgFile(cfgFile)
	if err != nil {
		return nil, err
	}

	if err := overrideWithEnv(opts); err != nil {
		return nil, err
	}

	slog.Info("Config loaded.", "config_file", cfgFile, slog.Any("config", opts))
	return opts, nil
}

func parseCfgFile(cfgFile string) (*Options, error) {
	cfgFile = filepath.Clean(cfgFile)
	configFile, err := os.ReadFile(cfgFile)
	if err != nil {
		return nil, fmt.Errorf("read config file %s: %w", cfgFile, err)
	}

	var opts Options
	if err := json.Unmarshal(configFile, &opts); err != nil {
		return nil, fmt.Errorf("decode json config %s: %w", configFile, err)
	}

	return &opts, nil
}

func overrideWithEnv(opts *Options) error {
	if url, ok := os.LookupEnv("URL"); ok {
		opts.Server.URL = url
	}

	if portStr, ok := os.LookupEnv("PORT"); ok {
		port, err := strconv.Atoi(portStr)
		if err != nil {
			return err
		}
		opts.Server.Port = port
	}
	return nil
}
