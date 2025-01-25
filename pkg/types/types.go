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

// A combined type of all related data for a service version
type ServiceVersionConfig struct {
	ServiceVersion
	Domains        []string `json:"domains" doc:"The domains used by the VCL"`
	Origins        []Origin `json:"origins" doc:"The origins used by the VCL"`
	VclRecvContent string   `json:"vcl_recv_content" doc:"The vcl_recv content for the service"`
}

type Origin struct {
	Host string `json:"host" minLength:"1" maxLength:"253"`
	Port int    `json:"port" minimum:"1" maximum:"65535"`
	TLS  bool   `json:"tls"`
}
