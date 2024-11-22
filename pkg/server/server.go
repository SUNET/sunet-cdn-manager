package server

import (
	"context"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strconv"
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
	// omitempty is needed to accept requests from clients that does not
	// include an ID (they are server generated).
	ID   int64  `jsonapi:"primary,customer,omitempty"`
	Name string `jsonapi:"attribute" json:"name"`
}

// Implements jsonapi.MarshalIdentifier
// Fixes "primary/id field must be a string or implement fmt.Stringer or in a
// struct which implements MarshalIdentifier" error
func (c *customer) MarshalID() string {
	// When using the customer struct in client mode (e.g. sending a POST
	// request to the server in tests) using jsonapi.MarshalClientMode() we
	// do not want to include the ID.
	//
	// The server generated IDs comes from a PostgreSQL sequence which
	// starts from 1 by default so if the value is 0 this means it is a
	// client mode request.
	if c.ID == 0 {
		return ""
	}
	return strconv.FormatInt(c.ID, 10)
}

type service struct {
	ID       int64     `jsonapi:"primary,services,omitempty"`
	Name     string    `jsonapi:"attribute" json:"name"`
	Customer *customer `jsonapi:"relationship" json:"customer"`
}

func (s *service) MarshalID() string {
	if s.ID == 0 {
		return ""
	}
	return strconv.FormatInt(s.ID, 10)
}

func (s *service) LinkRelation(relation string) *jsonapi.Link {
	id := strconv.FormatInt(s.ID, 10)
	return &jsonapi.Link{
		Self:    fmt.Sprintf("https://example.com/services/%s/relationships/%s", id, relation),
		Related: fmt.Sprintf("https://example.com/services/%s/%s", id, relation),
	}
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

func getCustomersHandler(dbPool *pgxpool.Pool) func(w http.ResponseWriter, req *http.Request) {
	return func(w http.ResponseWriter, req *http.Request) {
		logger := hlog.FromRequest(req)
		rows, err := dbPool.Query(context.Background(), "SELECT id, name FROM customers ORDER BY id")
		if err != nil {
			logger.Err(err).Msg("unable to Query for getCustomers")
			http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			return
		}
		customers, err := pgx.CollectRows(rows, pgx.RowToAddrOfStructByName[customer])
		if err != nil {
			logger.Err(err).Msg("unable to CollectRows for getCustomers")
			http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			return
		}

		b, err := jsonapi.Marshal(customers)
		if err != nil {
			logger.Err(err).Msg("unable to marshal getCustomers in API GET")
			http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			return
		}

		err = writeNewlineJSON(w, b, http.StatusOK)
		if err != nil {
			logger.Err(err).Msg("failed writing customersData in API GET")
			return
		}
	}
}

func getCustomerHandler(dbPool *pgxpool.Pool) func(w http.ResponseWriter, req *http.Request) {
	return func(w http.ResponseWriter, req *http.Request) {
		logger := hlog.FromRequest(req)

		id := req.PathValue("id")

		if id == "" {
			logger.Error().Msg("missing id PathValue getCustomer")
			http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
			return
		}

		idInt, err := strconv.ParseInt(id, 10, 64)
		if err != nil {
			logger.Err(err).Msg("unable to parse id integer for getCustomer")
			http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			return
		}

		var name string
		err = dbPool.QueryRow(context.Background(), "SELECT name FROM customers WHERE id=$1", idInt).Scan(&name)
		if err != nil {
			logger.Err(err).Int64("id", idInt).Msg("unable to SELECT customer by id")
			http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			return
		}

		c := &customer{
			ID:   idInt,
			Name: name,
		}

		b, err := jsonapi.Marshal(c)
		if err != nil {
			logger.Err(err).Msg("unable to marshal getCustomer in API GET")
			http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			return
		}

		err = writeNewlineJSON(w, b, http.StatusOK)
		if err != nil {
			logger.Err(err).Msg("failed writing customersData in API GET")
			return
		}
	}
}

func postCustomersHandler(dbPool *pgxpool.Pool) func(w http.ResponseWriter, req *http.Request) {
	return func(w http.ResponseWriter, req *http.Request) {
		logger := hlog.FromRequest(req)
		var id int64

		cReq := customer{}
		bodyData, err := io.ReadAll(req.Body)
		if err != nil {
			logger.Err(err).Msg("unable to read customer data in API POST")
			http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
			return
		}

		err = jsonapi.Unmarshal(bodyData, &cReq)
		if err != nil {
			logger.Err(err).Msg("unable to unmarshal customer in API POST")
			http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
			return
		}

		if cReq.Name == "" {
			je := jsonapi.Error{
				Status: jsonapi.Status(http.StatusBadRequest),
				Source: &jsonapi.ErrorSource{Pointer: "/data/attributes/name"},
				Title:  "Invalid Attribute",
				Detail: "Name must contain at least one character",
			}

			jeData, err := jsonapi.Marshal(je)
			if err != nil {
				logger.Err(err).Msg("unable to marshal JSON:API error")
				http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
				return
			}

			err = writeNewlineJSON(w, jeData, http.StatusBadRequest)
			if err != nil {
				logger.Err(err).Msg("postCustomers: unable to send error json")
			}
			return
		}

		err = dbPool.QueryRow(context.Background(), "INSERT INTO customers (name) VALUES ($1) RETURNING id", cReq.Name).Scan(&id)
		if err != nil {
			logger.Err(err).Msg("unable to INSERT customer")
			http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			return
		}

		cResp := customer{
			ID:   id,
			Name: cReq.Name,
		}

		b, err := jsonapi.Marshal(&cResp)
		if err != nil {
			logger.Err(err).Msg("unable to marshal customer in API POST")
			http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			return
		}

		err = writeNewlineJSON(w, b, http.StatusCreated)
		if err != nil {
			logger.Err(err).Msg("failed writing customersData in API POST")
			return
		}
	}
}

func getServicesHandler(dbPool *pgxpool.Pool) func(w http.ResponseWriter, req *http.Request) {
	return func(w http.ResponseWriter, req *http.Request) {
		logger := hlog.FromRequest(req)
		rows, err := dbPool.Query(context.Background(), "SELECT services.id, services.customer_id, services.name, customers.name FROM services JOIN customers ON services.customer_id = customers.id ORDER BY services.id")
		if err != nil {
			logger.Err(err).Msg("unable to Query for getServices")
			http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			return
		}
		services := []*service{}
		var serviceID, customerID int64
		var serviceName, customerName string
		_, err = pgx.ForEachRow(rows, []any{&serviceID, &customerID, &serviceName, &customerName}, func() error {
			services = append(
				services,
				&service{
					ID:   serviceID,
					Name: serviceName,
					Customer: &customer{
						Name: customerName,
						ID:   customerID,
					},
				},
			)
			return nil
		})
		if err != nil {
			logger.Err(err).Msg("unable to ForEachRow over services in API GET")
			http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			return
		}

		b, err := jsonapi.Marshal(services)
		if err != nil {
			logger.Err(err).Msg("unable to marshal getServers in API GET")
			http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			return
		}

		err = writeNewlineJSON(w, b, http.StatusOK)
		if err != nil {
			logger.Err(err).Msg("failed writing servicesData in API GET")
			return
		}
	}
}

func getServiceHandler(dbPool *pgxpool.Pool) func(w http.ResponseWriter, req *http.Request) {
	return func(w http.ResponseWriter, req *http.Request) {
		logger := hlog.FromRequest(req)

		id := req.PathValue("id")

		if id == "" {
			logger.Error().Msg("missing id PathValue getService")
			http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
			return
		}

		idInt, err := strconv.ParseInt(id, 10, 64)
		if err != nil {
			logger.Err(err).Msg("unable to parse id integer for getService")
			http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			return
		}

		var serviceName, customerName string
		var serviceID, customerID int64

		err = dbPool.QueryRow(context.Background(), "SELECT services.id, services.customer_id, services.name, customers.name FROM services JOIN customers ON services.customer_id = customers.id WHERE services.id=$1", idInt).Scan(&serviceID, &customerID, &serviceName, &customerName)
		if err != nil {
			logger.Err(err).Msg("unable to Query for getServices")
			http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			return
		}

		s := &service{
			ID:   serviceID,
			Name: serviceName,
			Customer: &customer{
				Name: customerName,
				ID:   customerID,
			},
		}

		b, err := jsonapi.Marshal(s)
		if err != nil {
			logger.Err(err).Msg("unable to marshal getServers in API GET")
			http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			return
		}

		err = writeNewlineJSON(w, b, http.StatusOK)
		if err != nil {
			logger.Err(err).Msg("failed writing servicesData in API GET")
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
	getCustomersChain := alice.New(rootMiddlewares...).ThenFunc(getCustomersHandler(dbPool))
	getCustomerChain := alice.New(rootMiddlewares...).ThenFunc(getCustomerHandler(dbPool))
	postCustomersChain := alice.New(rootMiddlewares...).ThenFunc(postCustomersHandler(dbPool))
	getServicesChain := alice.New(rootMiddlewares...).ThenFunc(getServicesHandler(dbPool))
	getServiceChain := alice.New(rootMiddlewares...).ThenFunc(getServiceHandler(dbPool))

	mux.Handle("/", rootChain)
	mux.Handle("GET /api/v1/customers", getCustomersChain)
	mux.Handle("GET /api/v1/customers/{id}", getCustomerChain)
	mux.Handle("POST /api/v1/customers", postCustomersChain)
	mux.Handle("GET /api/v1/services", getServicesChain)
	mux.Handle("GET /api/v1/services/{id}", getServiceChain)

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
