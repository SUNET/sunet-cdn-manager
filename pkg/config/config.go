package config

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/go-playground/validator/v10"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/spf13/viper"
)

// use a single instance of Validate, it caches struct info
var validate = validator.New(validator.WithRequiredStructEnabled())

type Config struct {
	Server              serverSettings
	DB                  dbSettings
	OIDC                oidcSettings
	Domains             domainSettings
	CertMagic           certmagicSettings
	AcmeDNS             acmeDNSConfig
	KeycloakClientAdmin keycloakClientAdminSettings `mapstructure:"keycloak_client_admin" validate:"required"`
}

type serverSettings struct {
	Addr             string `validate:"required"`
	VCLValidationURL string `mapstructure:"vcl_validation_url" validate:"required"`
}

type dbSettings struct {
	User           string        `validate:"required"`
	Password       string        `validate:"required"`
	DBName         string        `validate:"required"`
	Host           string        `validate:"required"`
	Port           int           `validate:"required"`
	SSLMode        string        `validate:"required"`
	CACertFilename string        `mapstructure:"ca_cert_filename"`
	QueryTimeout   time.Duration `mapstructure:"query_timeout" validate:"required,gt=5s"`
}

type oidcSettings struct {
	Issuer       string `validate:"required"`
	ClientID     string `mapstructure:"client_id" validate:"required"`
	ClientSecret string `mapstructure:"client_secret" validate:"required"`
	RedirectURL  string `mapstructure:"redirect_url" validate:"required"`
}

type keycloakClientAdminSettings struct {
	Realm          string `mapstructure:"realm" validate:"required"`
	BaseURL        string `mapstructure:"base_url" validate:"required"`
	ClientID       string `mapstructure:"client_id" validate:"required"`
	ClientSecret   string `mapstructure:"client_secret" validate:"required"`
	EncryptionKey  string `mapstructure:"encryption_key" validate:"required,min=15"`
	EncryptionSalt string `mapstructure:"encryption_salt" validate:"required,len=32,hexadecimal"`
}

type domainSettings struct {
	ResolverAddr   string        `mapstructure:"resolver_address" validate:"required"`
	VerifyInterval time.Duration `mapstructure:"verify_interval" validate:"required"`
}

type certmagicSettings struct {
	LetsEncryptProd bool     `mapstructure:"letsencrypt_prod"`
	Email           string   `mapstructure:"email"`
	Domains         []string `mapstructure:"domains"`
	DataDir         string   `mapstructure:"data-dir"`
}

type acmeDNSConfig map[string]acmeDNSDomainSettings

type acmeDNSDomainSettings struct {
	Username   string
	Password   string
	Subdomain  string
	FullDomain string `mapstructure:"full_domain"`
	ServerURL  string `mapstructure:"server_url"`
}

func GetConfig(localViper *viper.Viper) (Config, error) {
	var conf Config
	err := localViper.Unmarshal(&conf)
	if err != nil {
		return Config{}, fmt.Errorf("viper unable to decode into struct: %w", err)
	}

	err = validate.Struct(conf)
	if err != nil {
		return Config{}, fmt.Errorf("invalid config: %w", err)
	}

	return conf, nil
}

func certPoolFromFile(fileName string) (*x509.CertPool, error) {
	fileName = filepath.Clean(fileName)
	cert, err := os.ReadFile(fileName)
	if err != nil {
		return nil, fmt.Errorf("certPoolFromFile: unable to read file: %w", err)
	}
	certPool := x509.NewCertPool()
	ok := certPool.AppendCertsFromPEM(cert)
	if !ok {
		return nil, fmt.Errorf("certPoolFromFile: failed to append certs from PEM file '%s'", fileName)
	}

	return certPool, nil
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

	if conf.DB.CACertFilename != "" {
		// Setup CA cert for validating the postgresql server connection
		psqlCACertPool, err := certPoolFromFile(conf.DB.CACertFilename)
		if err != nil {
			return nil, fmt.Errorf("failed to create CA cert pool for PostgreSQL: %w", err)
		}

		pgConfig.ConnConfig.TLSConfig = &tls.Config{
			RootCAs:    psqlCACertPool,
			MinVersion: tls.VersionTLS13,
			ServerName: conf.DB.Host,
		}
	}

	return pgConfig, nil
}
