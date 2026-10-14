package config

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/go-playground/validator/v10"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/spf13/viper"
)

// use a single instance of Validate, it caches struct info
var validate = validator.New(validator.WithRequiredStructEnabled())

// KeyDelimiter is the viper key delimiter the config is read with. It is not
// the default "." because config such as [acmedns."manager-test.cdn.sunet.se"]
// has keys containing dots. Every viper instance passed to GetConfig must be
// created with viper.KeyDelimiter(KeyDelimiter), and keys set programmatically
// (defaults, overrides) must be built with key() so they nest correctly.
const KeyDelimiter = "::"

// key builds a nested viper key using KeyDelimiter.
func key(parts ...string) string {
	return strings.Join(parts, KeyDelimiter)
}

type Config struct {
	Server              serverSettings
	DB                  dbSettings
	OIDC                oidcSettings
	Domains             domainSettings
	CertMagic           certmagicSettings
	AcmeDNS             acmeDNSConfig
	KeycloakClientAdmin keycloakClientAdminSettings `mapstructure:"keycloak_client_admin" validate:"required"`
	Login               loginSettings
}

type serverSettings struct {
	URL                  string        `validate:"required,https_url"`
	Addr                 string        `validate:"required"`
	VCLValidationURL     string        `mapstructure:"vcl_validation_url" validate:"required"`
	ConsoleSessionMaxAge time.Duration `mapstructure:"console_session_max_age" validate:"required,min=1s"`
	ConsoleSessionCapAge time.Duration `mapstructure:"console_session_cap_age" validate:"required,min=1s,gtefield=ConsoleSessionMaxAge"`
	// Server WriteTimeout. Optional, it defaults to and can not be lower
	// than minWriteTimeout(), see GetConfig(). Each request gets this minus
	// a small margin for writing the response to do its work.
	WriteTimeout time.Duration `mapstructure:"write_timeout"`
}

// loginSettings controls the cost of local password verification. All keys
// are optional, see setLoginDefaults().
type loginSettings struct {
	// Max number of concurrent argon2 hash calculations, each one uses
	// about 64 MiB of memory with the default argon2 settings
	Argon2MaxConcurrent int `mapstructure:"argon2_max_concurrent" validate:"min=1"`
	// Max time to wait for a free argon2 slot before answering "busy". A
	// password change shares this budget between its two hashes. The
	// server WriteTimeout grows with this value, the upper bound is there
	// because a login hanging for longer than that before saying "busy"
	// is not useful to anyone.
	Argon2WaitTimeout time.Duration `mapstructure:"argon2_wait_timeout" validate:"min=100ms,max=4s"`
	// Number of password verifications needing a hash that a single
	// client IP (IPv6 /64) can do in a burst
	IPRateBurst int `mapstructure:"ip_rate_burst" validate:"min=1"`
	// One more such verification is allowed per interval
	IPRateInterval time.Duration `mapstructure:"ip_rate_interval" validate:"gt=0s"`
}

// setLoginDefaults makes the [login] table optional so existing configs keep
// working.
func setLoginDefaults(localViper *viper.Viper) {
	localViper.SetDefault(key("login", "argon2_max_concurrent"), 1)
	localViper.SetDefault(key("login", "argon2_wait_timeout"), 3*time.Second)
	localViper.SetDefault(key("login", "ip_rate_burst"), 10)
	localViper.SetDefault(key("login", "ip_rate_interval"), 6*time.Second)
}

type dbSettings struct {
	User           string        `validate:"required"`
	Password       string        `validate:"required"` // #nosec G117 -- Used to build psql config string, never used for serialized output
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
	ClientSecret string `mapstructure:"client_secret" validate:"required"` // #nosec G117 -- Used for configuration, never used for serialized output
	RedirectURL  string `mapstructure:"redirect_url" validate:"required"`
}

type keycloakClientAdminSettings struct {
	Realm               string   `mapstructure:"realm" validate:"required"`
	BaseURL             string   `mapstructure:"base_url" validate:"required"`
	ClientID            string   `mapstructure:"client_id" validate:"required"`
	ClientSecret        string   `mapstructure:"client_secret" validate:"required"` // #nosec G117 -- Used for configuration, never used for serialized output
	EncryptionPasswords []string `mapstructure:"encryption_passwords" validate:"required,gt=0,unique,dive,min=15"`
	EncryptionSalt      string   `mapstructure:"encryption_salt" validate:"required,len=32,hexadecimal"`
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
	Password   string // #nosec G117 -- Used to fill in acme config, never used for serialized output
	Subdomain  string
	FullDomain string `mapstructure:"full_domain"`
	ServerURL  string `mapstructure:"server_url"`
}

func GetConfig(localViper *viper.Viper) (Config, error) {
	setLoginDefaults(localViper)

	var conf Config
	err := localViper.Unmarshal(&conf)
	if err != nil {
		return Config{}, fmt.Errorf("viper unable to decode into struct: %w", err)
	}

	err = validate.Struct(conf)
	if err != nil {
		return Config{}, fmt.Errorf("invalid config: %w", err)
	}

	err = setWriteTimeout(&conf)
	if err != nil {
		return Config{}, fmt.Errorf("invalid config: %w", err)
	}

	return conf, nil
}

// minWriteTimeout keeps the server write timeout used before it became
// configurable. It reserves one db.query_timeout, two
// login.argon2_wait_timeout for the hashing slot waits of a password change
// (Basic auth check and new password) and 5s for the hashing itself and other
// fast database steps. It is not a guarantee: a request where several
// database steps are slow can need more, it then fails at its deadline.
func minWriteTimeout(conf Config) time.Duration {
	return conf.DB.QueryTimeout + 2*conf.Login.Argon2WaitTimeout + 5*time.Second
}

// setWriteTimeout makes server.write_timeout optional. It can only be raised
// above the minimum, e.g. temporarily for a long running request like
// re-encrypting org client credentials. Struct tags can not compare values
// across config sections so this is checked here.
func setWriteTimeout(conf *Config) error {
	minTimeout := minWriteTimeout(*conf)
	switch {
	case conf.Server.WriteTimeout == 0:
		conf.Server.WriteTimeout = minTimeout
	case conf.Server.WriteTimeout < minTimeout:
		return fmt.Errorf("server.write_timeout %s is lower than the minimum %s (db.query_timeout + 2*login.argon2_wait_timeout + 5s)", conf.Server.WriteTimeout, minTimeout)
	}

	return nil
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
