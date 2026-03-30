vcl {{.VCLVersion}};
{{range .Modules }}
import {{.}};
{{- end }}

# Set default backend to special "none" which will always fail (503). This way
# we will not accidentally fall back to "first backend found in the vcl" which
# could lead to confusing results. This requires the VCL to always explicitly
# set req.backend_hint for things to work.
backend default none;

# Origin group backends
{{- range $originGroup := $.OriginGroups }}
{{- if $originGroup.HTTPS }}
backend {{$originGroup.Name}}_https {
  .path = "/shared/unix-sockets/haproxy_{{$originGroup.Name}}_https";
  .proxy_header = 2;
}
{{- end}}
{{- if $originGroup.HTTP }}
backend {{$originGroup.Name}}_http {
  .path = "/shared/unix-sockets/haproxy_{{$originGroup.Name}}_http";
  .proxy_header = 2;
}
{{- end}}
{{- end}}
