package config

import (
	"fmt"
	"time"

	"github.com/go-playground/validator/v10"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/spf13/viper"
)

// use a single instance of Validate, it caches struct info
var validate = validator.New(validator.WithRequiredStructEnabled())

type Config struct {
	Server  serverSettings
	DB      dbSettings
	OIDC    oidcSettings
	Domains domainSettings
}

type serverSettings struct {
	Addr             string `validate:"required"`
	VCLValidationURL string `mapstructure:"vcl_validation_url" validate:"required"`
}

type dbSettings struct {
	User     string `validate:"required"`
	Password string `validate:"required"`
	DBName   string `validate:"required"`
	Host     string `validate:"required"`
	Port     int    `validate:"required"`
	SSLMode  string `validate:"required"`
}

type oidcSettings struct {
	Issuer       string `validate:"required"`
	ClientID     string `mapstructure:"client_id" validate:"required"`
	ClientSecret string `mapstructure:"client_secret" validate:"required"`
	RedirectURL  string `mapstructure:"redirect_url" validate:"required"`
}

type domainSettings struct {
	ResolverAddr   string        `mapstructure:"resolver_address" validate:"required"`
	VerifyInterval time.Duration `mapstructure:"verify_interval" validate:"required"`
}

func GetConfig() (Config, error) {
	var conf Config
	err := viper.Unmarshal(&conf)
	if err != nil {
		return Config{}, fmt.Errorf("viper unable to decode into struct: %w", err)
	}

	err = validate.Struct(conf)
	if err != nil {
		return Config{}, fmt.Errorf("invalid config: %w", err)
	}

	return conf, nil
}

func (conf Config) PGConfig() (*pgxpool.Config, error) {
	pgConfigString := fmt.Sprintf(
		"user=%s password=%s host=%s port=%d dbname=%s sslmode=%s",
		conf.DB.User,
		conf.DB.Password,
		conf.DB.Host,
		conf.DB.Port,
		conf.DB.DBName,
		conf.DB.SSLMode,
	)

	pgConfig, err := pgxpool.ParseConfig(pgConfigString)
	if err != nil {
		return nil, fmt.Errorf("unable to parse PostgreSQL config string: %w", err)
	}

	return pgConfig, nil
}
