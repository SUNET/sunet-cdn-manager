package types

import (
	"net/netip"

	"github.com/danielgtaylor/huma/v2"
	"github.com/jackc/pgx/v5/pgtype"
)

// Types that can be shared across the other packages
type Org struct {
	ID   pgtype.UUID `json:"id" doc:"ID of organization, UUIDv4"`
	Name string      `json:"name" example:"organization 1" doc:"name of organization"`
}

type Service struct {
	ID            pgtype.UUID `json:"id" doc:"ID of service"`
	Name          string      `json:"name" example:"service 1" doc:"name of service"`
	OrgID         pgtype.UUID `json:"org_id" doc:"ID of related organization"`
	OrgName       string      `json:"org_name" doc:"Name of related organization"`
	UIDRangeFirst int64       `json:"uid_range_first" doc:"First process UID allocated to this service" db:"uid_range_first"`
	UIDRangeEnd   int64       `json:"uid_range_last" doc:"Last UID allocated to this service" db:"uid_range_last"`
}

type ServiceVersion struct {
	ID          pgtype.UUID `json:"id" doc:"ID of the service version"`
	ServiceID   pgtype.UUID `json:"service_id" doc:"ID of related service"`
	ServiceName string      `json:"service_name" doc:"Name of related service"`
	OrgID       pgtype.UUID `json:"org_id" doc:"ID of related organization"`
	OrgName     string      `json:"org_name" doc:"Name of related organization"`
	Version     int64       `json:"version" example:"1" doc:"Version of the service"`
	Active      bool        `json:"active" example:"true" doc:"If the version is active"`
}

type ServiceVersionVCL struct {
	ServiceVersion
	VCL string `json:"vcl" example:"varnish vcl" doc:"VCL content"`
}

// A combined type of all related data for a service version
type ServiceVersionConfig struct {
	ServiceVersion
	VclSteps
	SNIHostname        *string        `json:"sni_hostname" doc:"The name that should be present in the TLS cert presented by TLS origins" validate:"omitnil,min=1,max=253"`
	ServiceIPAddresses []netip.Addr   `json:"service_ip_addresses" doc:"The IP (v4 and v6) addresses allocated to the service" validate:"min=2"`
	Domains            []DomainString `json:"domains" doc:"The domains used by the VCL" validate:"min=1"`
	Origins            []Origin       `json:"origins" doc:"The origins used by the VCL" validate:"min=1"`
}

// What data is expected when handling a request to add a version version
type InputServiceVersion struct {
	ServiceVersion
	VclSteps
	SNIHostname *string        `json:"sni_hostname" doc:"The name that should be present in the TLS cert presented by TLS origins" validate:"omitnil,min=1,max=253"`
	Domains     []DomainString `json:"domains" doc:"The domains used by the VCL" validate:"min=1"`
	Origins     []Origin       `json:"origins" doc:"The origins used by the VCL" validate:"min=1"`
}

type Origin struct {
	Host string `json:"host" minLength:"1" maxLength:"253"`
	Port int    `json:"port" minimum:"1" maximum:"65535"`
	TLS  bool   `json:"tls"`
}

// The "Client" and "Backend" steps from
// https://varnish-cache.org/docs/trunk/reference/vcl-step.html
// Fields are pointers to strings since they can all potentially be NULL in the database.
type VclSteps struct {
	VclRecv            *string `json:"vcl_recv,omitempty" doc:"The vcl_recv content" schema:"vcl_recv" validate:"omitnil,min=1,max=2048"`
	VclPipe            *string `json:"vcl_pipe,omitempty" doc:"The vcl_pipe content" schema:"vcl_pipe" validate:"omitnil,min=1,max=2048"`
	VclPass            *string `json:"vcl_pass,omitempty" doc:"The vcl_pass content" schema:"vcl_pass" validate:"omitnil,min=1,max=2048"`
	VclHash            *string `json:"vcl_hash,omitempty" doc:"The vcl_hash content" schema:"vcl_hash" validate:"omitnil,min=1,max=2048"`
	VclPurge           *string `json:"vcl_purge,omitempty" doc:"The vcl_purge content" schema:"vcl_purge" validate:"omitnil,min=1,max=2048"`
	VclMiss            *string `json:"vcl_miss,omitempty" doc:"The vcl_miss content" schema:"vcl_miss" validate:"omitnil,min=1,max=2048"`
	VclHit             *string `json:"vcl_hit,omitempty" doc:"The vcl_hit content" schema:"vcl_hit" validate:"omitnil,min=1,max=2048"`
	VclDeliver         *string `json:"vcl_deliver,omitempty" doc:"The vcl_deliver content" schema:"vcl_deliver" validate:"omitnil,min=1,max=2048"`
	VclSynth           *string `json:"vcl_synth,omitempty" doc:"The vcl_synth content" schema:"vcl_synth" validate:"omitnil,min=1,max=2048"`
	VclBackendFetch    *string `json:"vcl_backend_fetch,omitempty" doc:"The vcl_backend_fetch content" schema:"vcl_backend_fetch" validate:"omitnil,min=1,max=2048"`
	VclBackendResponse *string `json:"vcl_backend_response,omitempty" doc:"The vcl_backend_response content" schema:"vcl_backend_response" validate:"omitnil,min=1,max=2048"`
	VclBackendError    *string `json:"vcl_backend_error,omitempty" doc:"The vcl_backend_error content" schema:"vcl_backend_error" validate:"omitnil,min=1,max=2048"`
}

// Nested struct containing complete config for a cache node optimized for easy
// iteration over the contents and minimal duplication of fields.
//
// Map key is string rather than pgtype.UUID to support JSON marshalling.
// Trying to use pgtype.UUID directly as a map key leads to
// "json: unsupported type: map[pgtype.UUID]string"
// because pgtype.UUID does not implement encoding.TextMarshaler as expected by
// encoding/json.
type CacheNodeConfig struct {
	Orgs map[string]OrgWithServices `json:"orgs"`
}

type OrgWithServices struct {
	ID       pgtype.UUID                    `json:"id"`
	Name     string                         `json:"name"`
	Services map[string]ServiceWithVersions `json:"services"`
}

type ServiceWithVersions struct {
	ID              pgtype.UUID                        `json:"id"`
	Name            string                             `json:"name"`
	UIDRangeFirst   int64                              `json:"uid_range_first"`
	UIDRangeLast    int64                              `json:"uid_range_last"`
	ServiceVersions map[int64]ServiceVersionWithConfig `json:"service_versions"`
}

type ServiceVersionWithConfig struct {
	ID            pgtype.UUID    `json:"id"`
	Version       int64          `json:"version" example:"1" doc:"Version of the service"`
	Active        bool           `json:"active" example:"true" doc:"If the version is active"`
	VCL           string         `json:"vcl"`
	TLS           bool           `json:"tls" example:"true" doc:"If at least one origin has TLS enabled which means we require certificates"`
	Domains       []DomainString `json:"domains" doc:"Names that the service is listening on"`
	HAProxyConfig string         `json:"haproxy_config"`
}

type VclStepKeys struct {
	FieldOrder []string
	FieldToKey map[string]string
}

func Ptr[T any](v T) *T {
	return &v
}

type DomainString string

func (ds DomainString) Schema(_ huma.Registry) *huma.Schema {
	return &huma.Schema{
		Type:      "string",
		MinLength: Ptr(1),
		MaxLength: Ptr(253),
	}
}

func (ds DomainString) String() string {
	return string(ds)
}
