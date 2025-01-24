package types

import (
	"github.com/jackc/pgx/v5/pgtype"
)

// Types that can be shared across the other packages

// A 1:1 mapping to service_versions in the database
type ServiceVersion struct {
	ID      pgtype.UUID `json:"id"`
	Version int64       `json:"version" example:"1" doc:"Version of the service"`
	Active  bool        `json:"active" example:"true" doc:"If the VCL is active"`
}

// A combined type of all related data for a service version
type ServiceVersionConfig struct {
	ServiceVersion
	ServiceID      pgtype.UUID `json:"service_id" doc:"ID of service"`
	Domains        []string    `json:"domains" doc:"The domains used by the VCL"`
	Origins        []Origin    `json:"origins" doc:"The origins used by the VCL"`
	VclRecvContent string      `json:"vcl_recv_content" doc:"The vcl_recv content for the service"`
}

type Origin struct {
	Host string `json:"host" minLength:"1" maxLength:"253"`
	Port int    `json:"port" minimum:"1" maximum:"65535"`
	TLS  bool   `json:"tls"`
}
