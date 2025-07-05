package env_test

import (
	"reflect"
	"testing"

	"github.com/ferdiebergado/kubokit/internal/pkg/env"
)

func TestOverrideStruct(t *testing.T) {
	const (
		wantEnv     = "testing"
		wantCons    = 10
		wantConsStr = "10"
	)

	type dbOpts struct {
		MaxOpenConn int `env:"DB_MAX_OPEN_CONNS"`
	}

	type settings struct {
		Env    string `env:"ENV"`
		DBOpts *dbOpts
	}

	got := settings{
		Env: "development",
		DBOpts: &dbOpts{
			MaxOpenConn: 3,
		},
	}

	t.Setenv("ENV", wantEnv)
	t.Setenv("DB_MAX_OPEN_CONNS", wantConsStr)

	if err := env.OverrideStruct(&got); err != nil {
		t.Fatal(err)
	}

	want := settings{
		Env: "testing",
		DBOpts: &dbOpts{
			MaxOpenConn: wantCons,
		},
	}

	if !reflect.DeepEqual(got, want) {
		t.Errorf("env.OverrideStruct(&got) = %+v, want: %+v", got, want)
	}
}

func TestEnv(t *testing.T) {
	const fallback = "example.com"

	tests := []struct {
		name, envVar, envVal, fallback, val string
	}{
		{"EnvVar is set", "HOST", "localhost", fallback, "localhost"},
		{"EnvVar is not set", "HOST", "", fallback, fallback},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if tc.envVal != "" {
				t.Setenv(tc.envVar, tc.envVal)
			}
			val := env.Env(tc.envVar, tc.fallback)

			if val != tc.val {
				t.Errorf("env.Env(%q, %q) = %q, want: %q", tc.envVar, tc.fallback, val, tc.val)
			}
		})
	}
}
