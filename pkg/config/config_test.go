package config

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/spf13/viper"
)

// loadSampleConfig reads the sample config shipped in the repo root. It has
// no active [login] table, so it doubles as an "existing deployment" config.
func loadSampleConfig(t *testing.T) *viper.Viper {
	t.Helper()

	v := viper.New()
	v.SetConfigFile(filepath.Join("..", "..", "sunet-cdn-manager.toml.sample"))
	// The ".sample" extension is not a known config type
	v.SetConfigType("toml")
	err := v.ReadInConfig()
	if err != nil {
		t.Fatal(err)
	}

	return v
}

func TestGetConfigLoginDefaults(t *testing.T) {
	conf, err := GetConfig(loadSampleConfig(t))
	if err != nil {
		t.Fatal(err)
	}

	want := loginSettings{
		Argon2MaxConcurrent: 1,
		Argon2WaitTimeout:   3 * time.Second,
		IPRateBurst:         10,
		IPRateInterval:      6 * time.Second,
	}

	if conf.Login != want {
		t.Fatalf("unexpected login defaults, want: %+v, got: %+v", want, conf.Login)
	}
}

func TestGetConfigLoginOverride(t *testing.T) {
	v := loadSampleConfig(t)
	v.Set("login.argon2_max_concurrent", 2)
	v.Set("login.argon2_wait_timeout", "2s")
	v.Set("login.ip_rate_burst", 3)
	v.Set("login.ip_rate_interval", "1m")

	conf, err := GetConfig(v)
	if err != nil {
		t.Fatal(err)
	}

	want := loginSettings{
		Argon2MaxConcurrent: 2,
		Argon2WaitTimeout:   2 * time.Second,
		IPRateBurst:         3,
		IPRateInterval:      time.Minute,
	}

	if conf.Login != want {
		t.Fatalf("unexpected login settings, want: %+v, got: %+v", want, conf.Login)
	}
}

func TestGetConfigLoginInvalid(t *testing.T) {
	tests := []struct {
		description string
		key         string
		value       any
	}{
		{description: "zero argon2 slots", key: "login.argon2_max_concurrent", value: 0},
		{description: "too short argon2 wait", key: "login.argon2_wait_timeout", value: "10ms"},
		{description: "too long argon2 wait", key: "login.argon2_wait_timeout", value: "5s"},
		{description: "zero burst", key: "login.ip_rate_burst", value: 0},
		{description: "zero interval", key: "login.ip_rate_interval", value: "0s"},
	}

	for _, test := range tests {
		t.Run(test.description, func(t *testing.T) {
			v := loadSampleConfig(t)
			v.Set(test.key, test.value)

			_, err := GetConfig(v)
			if err == nil {
				t.Fatalf("expected validation error for %s=%v", test.key, test.value)
			}
		})
	}
}
