vcl {{.VCLVersion}};
{{range .Modules }}
import {{.}};
{{- end }}

# Set default backend to special "none" which will always fail (503). This way
# we will not accidentally fall back to "first backend found in the vcl" which
# could lead to confusing results. This requires the VCL to always explicitly
# set req.backend_hint for things to work.
backend default none;

# Origin group backends. Each points at a haproxy frontend that handles TLS,
# DNS and load balancing towards the origin servers. No .proxy_header is
# set: it would limit each backend connection to a single request as documented
# at
# https://vinyl-cache.org/docs/9.1/reference/vcl-backend.html#attribute-proxy-header.
# haproxy instead takes the client address from the last X-Forwarded-For
# element which vinyl always appends.
{{- range $originGroup := $.OriginGroups }}
{{- if $originGroup.HTTPS }}
backend {{$originGroup.Name}}_https {
  .path = "/shared/unix-sockets/haproxy_{{$originGroup.Name}}_https";
}
{{- end}}
{{- if $originGroup.HTTP }}
backend {{$originGroup.Name}}_http {
  .path = "/shared/unix-sockets/haproxy_{{$originGroup.Name}}_http";
}
{{- end}}
{{- end}}
