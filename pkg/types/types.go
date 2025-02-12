package types

import (
	"github.com/jackc/pgx/v5/pgtype"
)

// Types that can be shared across the other packages

type Service struct {
	ID      pgtype.UUID `json:"id" doc:"ID of service"`
	Name    string      `json:"name" example:"service 1" doc:"name of service"`
	OrgID   pgtype.UUID `json:"org_id" doc:"ID of related organization"`
	OrgName string      `json:"org_name" doc:"Name of related organization"`
}

type ServiceVersion struct {
	ID          pgtype.UUID `json:"id"`
	ServiceID   pgtype.UUID `json:"service_id" doc:"ID of related service"`
	ServiceName string      `json:"service_name" doc:"Name of related service"`
	OrgID       pgtype.UUID `json:"org_id" doc:"ID of related organization"`
	OrgName     string      `json:"org_name" doc:"Name of related organization"`
	Version     int64       `json:"version" example:"1" doc:"Version of the service"`
	Active      bool        `json:"active" example:"true" doc:"If the VCL is active"`
}

type ServiceVersionVCL struct {
	ServiceID   pgtype.UUID `json:"service_id" doc:"ID of related service"`
	ServiceName string      `json:"service_name" doc:"Name of related service"`
	OrgID       pgtype.UUID `json:"org_id" doc:"ID of related organization"`
	OrgName     string      `json:"org_name" doc:"Name of related organization"`
	Version     int64       `json:"version" example:"1" doc:"Version of the service"`
	VCL         string      `json:"vcl" example:"varnish vcl" doc:"VCL content"`
}

// A combined type of all related data for a service version
type ServiceVersionConfig struct {
	ServiceVersion
	VclSteps
	Domains []string `json:"domains" doc:"The domains used by the VCL"`
	Origins []Origin `json:"origins" doc:"The origins used by the VCL"`
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
	VclRecv            *string `json:"vcl_recv,omitempty" doc:"The vcl_recv content" schema:"vcl_recv" validate:"omitnil,min=1,max=63"`
	VclPipe            *string `json:"vcl_pipe,omitempty" doc:"The vcl_pipe content" schema:"vcl_pipe" validate:"omitnil,min=1,max=63"`
	VclPass            *string `json:"vcl_pass,omitempty" doc:"The vcl_pass content" schema:"vcl_pass" validate:"omitnil,min=1,max=63"`
	VclHash            *string `json:"vcl_hash,omitempty" doc:"The vcl_hash content" schema:"vcl_hash" validate:"omitnil,min=1,max=63"`
	VclPurge           *string `json:"vcl_purge,omitempty" doc:"The vcl_purge content" schema:"vcl_purge" validate:"omitnil,min=1,max=63"`
	VclMiss            *string `json:"vcl_miss,omitempty" doc:"The vcl_miss content" schema:"vcl_miss" validate:"omitnil,min=1,max=63"`
	VclHit             *string `json:"vcl_hit,omitempty" doc:"The vcl_hit content" schema:"vcl_hit" validate:"omitnil,min=1,max=63"`
	VclDeliver         *string `json:"vcl_deliver,omitempty" doc:"The vcl_deliver content" schema:"vcl_deliver" validate:"omitnil,min=1,max=63"`
	VclSynth           *string `json:"vcl_synth,omitempty" doc:"The vcl_synth content" schema:"vcl_synth" validate:"omitnil,min=1,max=63"`
	VclBackendFetch    *string `json:"vcl_backend_fetch,omitempty" doc:"The vcl_backend_fetch content" schema:"vcl_backend_fetch" validate:"omitnil,min=1,max=63"`
	VclBackendResponse *string `json:"vcl_backend_response,omitempty" doc:"The vcl_backend_response content" schema:"vcl_backend_response" validate:"omitnil,min=1,max=63"`
	VclBackendError    *string `json:"vcl_backend_error,omitempty" doc:"The vcl_backend_error content" schema:"vcl_backend_error" validate:"omitnil,min=1,max=63"`
}

type VclStepKeys struct {
	FieldOrder []string
	FieldToKey map[string]string
}
