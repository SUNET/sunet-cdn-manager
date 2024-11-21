package server

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/DataDog/jsonapi"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/justinas/alice"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/hlog"
	"github.com/spf13/viper"
)

const (
	contentTypeString string = "application/json; charset=utf-8"
)

type config struct {
	DB dbSettings
}

type dbSettings struct {
	User     string
	Password string
	DBName   string
	Host     string
	Port     int
	SSLMode  string
}

type customer struct {
	ID   string `jsonapi:"primary,customers"`
	Name string `jsonapi:"attribute" json:"name"`
}

// Small struct that implements io.Writer so we can pass it to net/http server
// for error logging
type zerologErrorWriter struct {
	logger *zerolog.Logger
}

func (zew *zerologErrorWriter) Write(p []byte) (n int, err error) {
	zew.logger.Error().Msg(strings.TrimSuffix(string(p), "\n"))
	return len(p), nil
}

func rootHandler(w http.ResponseWriter, req *http.Request) {
	if req.Method != http.MethodGet {
		http.Error(w, http.StatusText(http.StatusMethodNotAllowed), http.StatusMethodNotAllowed)
		return
	}

	// The "/" pattern matches everything, so we need to check
	// that we're at the root here.
	if req.URL.Path != "/" {
		http.NotFound(w, req)
		return
	}

	fmt.Fprintf(w, "Welcome to SUNET CDN Manager\n")
}

func writeNewlineJSON(w http.ResponseWriter, b []byte, statusCode int) error {
	w.Header().Set("content-type", contentTypeString)
	w.WriteHeader(statusCode)
	// Include newline since this JSON can be returned to curl
	// requests and similar where the prompt gets messed up without
	// it.
	_, err := fmt.Fprintf(w, "%s\n", b)
	if err != nil {
		return err
	}

	return nil
}

func getCustomersHandler(logger zerolog.Logger, dbPool *pgxpool.Pool) func(w http.ResponseWriter, req *http.Request) {
	return func(w http.ResponseWriter, _ *http.Request) {
		rows, err := dbPool.Query(context.Background(), "SELECT id, name FROM customers")
		if err != nil {
			logger.Err(err).Msg("unable to Query for getCustomers")
			http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			return
		}
		customers, err := pgx.CollectRows(rows, pgx.RowToStructByName[customer])
		if err != nil {
			logger.Err(err).Msg("unable to CollectRows for getCustomers")
			http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			return
		}

		b, err := jsonapi.Marshal(&customers)
		if err != nil {
			logger.Err(err).Msg("unable to marshal getCustomers in API GET")
			http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			return
		}

		err = writeNewlineJSON(w, b, http.StatusOK)
		if err != nil {
			logger.Err(err).Msg("failed writing lockStatusData in API GET")
			return
		}
	}
}

func newHlogMiddlewares(logger zerolog.Logger) []alice.Constructor {
	hlogMiddlewares := []alice.Constructor{
		// hlog handlers based on example from https://github.com/rs/zerolog#integration-with-nethttp
		hlog.NewHandler(logger),
		hlog.AccessHandler(func(r *http.Request, status, size int, duration time.Duration) {
			hlog.FromRequest(r).Info().
				Str("method", r.Method).
				Stringer("url", r.URL).
				Int("status", status).
				Int("size", size).
				Dur("duration", duration).
				Msg("")
		}),
		hlog.RemoteAddrHandler("ip"),
		hlog.UserAgentHandler("user_agent"),
		hlog.RefererHandler("referer"),
		hlog.RequestIDHandler("req_id", "Request-Id"),
	}

	return hlogMiddlewares
}

func newRootMiddlewares(hlogMiddlewares []alice.Constructor) []alice.Constructor {
	fleetLockMiddlewares := []alice.Constructor{}
	fleetLockMiddlewares = append(fleetLockMiddlewares, hlogMiddlewares...)

	return fleetLockMiddlewares
}

func newMux(logger zerolog.Logger, dbPool *pgxpool.Pool) *http.ServeMux {
	mux := http.NewServeMux()

	hlogMiddlewares := newHlogMiddlewares(logger)
	rootMiddlewares := newRootMiddlewares(hlogMiddlewares)

	rootChain := alice.New(rootMiddlewares...).ThenFunc(rootHandler)
	getCustomersChain := alice.New(rootMiddlewares...).ThenFunc(getCustomersHandler(logger, dbPool))

	mux.Handle("/", rootChain)
	mux.Handle("GET /api/v1/customers", getCustomersChain)

	return mux
}

func Run(logger zerolog.Logger) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Exit gracefully on SIGINT or SIGTERM
	go func(logger zerolog.Logger, cancel context.CancelFunc) {
		sigCh := make(chan os.Signal, 1)
		signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)
		s := <-sigCh
		logger.Info().Str("signal", s.String()).Msg("received signal")
		cancel()
	}(logger, cancel)

	var conf config
	err := viper.Unmarshal(&conf)
	if err != nil {
		logger.Fatal().Err(err).Msg("viper unable to decode into struct")
	}

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
		logger.Fatal().Err(err).Msg("unable to parse PostgreSQL config string")
	}

	dbPool, err := pgxpool.NewWithConfig(ctx, pgConfig)
	if err != nil {
		logger.Fatal().Err(err).Msg("unable to create database pool")
	}
	defer dbPool.Close()

	err = dbPool.Ping(context.Background())
	if err != nil {
		logger.Fatal().Err(err).Msg("unable to ping database connection")
	}

	mux := newMux(logger, dbPool)

	srv := &http.Server{
		Addr:         "127.0.0.1:8080",
		Handler:      mux,
		ReadTimeout:  time.Second * 10,
		WriteTimeout: time.Second * 10,
		ErrorLog:     log.New(&zerologErrorWriter{&logger}, "", 0),
	}

	// Handle graceful shutdown of HTTP server when receiving signal
	idleConnsClosed := make(chan struct{})

	go func(ctx context.Context, logger zerolog.Logger) {
		<-ctx.Done()

		shutdownDelay := time.Second * 5
		logger.Info().Msgf("sleeping for %s then calling Shutdown()", shutdownDelay)
		time.Sleep(shutdownDelay)
		if err := srv.Shutdown(context.Background()); err != nil {
			// Error from closing listeners, or context timeout:
			logger.Err(err).Msg("HTTP server Shutdown failure")
		}
		close(idleConnsClosed)
	}(ctx, logger)

	if err := srv.ListenAndServe(); err != http.ErrServerClosed {
		logger.Fatal().Err(err).Msg("HTTP server ListenAndServe failed")
	}

	<-idleConnsClosed
}
