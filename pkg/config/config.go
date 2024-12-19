package config

import (
	"fmt"

	"github.com/go-playground/validator/v10"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/spf13/viper"
)

// use a single instance of Validate, it caches struct info
var validate *validator.Validate

type Config struct {
	Server serverSettings
	DB     dbSettings
}

type serverSettings struct {
	Addr string
}

type dbSettings struct {
	User     string `validate:"required"`
	Password string `validate:"required"`
	DBName   string `validate:"required"`
	Host     string `validate:"required"`
	Port     int    `validate:"required"`
	SSLMode  string `validate:"required"`
}

func GetConfig() (Config, error) {
	var conf Config
	err := viper.Unmarshal(&conf)
	if err != nil {
		return Config{}, fmt.Errorf("viper unable to decode into struct: %w", err)
	}

	validate = validator.New(validator.WithRequiredStructEnabled())
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
