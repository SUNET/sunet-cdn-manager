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

sub vcl_recv {
  if ({{ range $index, $domain := $.Domains }}{{if gt $index 0}} && {{end}}req.http.host != "{{$domain}}"{{end}}) {
    return(synth(400,"Unknown Host header."));
  }
  if (proxy.is_ssl()) {
    {{- if .HTTPSEnabled}}
    set req.http.X-Forwarded-Proto = "https";
    {{- if .DefaultForHTTPS}}
    set req.backend_hint = {{$.DefaultOriginGroupName}}_https;
    {{- end}}
    {{- else}}
    return(synth(400,"HTTPS request but no HTTPS origin available."));
    {{- end}}
  } else {
    {{- if .HTTPEnabled}}
    set req.http.X-Forwarded-Proto = "http";
    {{- if $.DefaultForHTTP}}
    set req.backend_hint = {{$.DefaultOriginGroupName}}_http;
    {{- end}}
    {{- else}}
    return(synth(400,"HTTP request but no HTTP origin available."));
    {{- end}}
  }

# START vcl_recv content
{{- if .VCLSteps.VclRecv}}
{{.VCLSteps.VclRecv}}
{{- end}}
# END vcl_recv content
}

# START vcl_pipe content
{{- if .VCLSteps.VclPipe}}
sub vcl_pipe {
{{.VCLSteps.VclPipe}}
}
{{- end}}
# END vcl_pipe content

# START vcl_pass content
{{- if .VCLSteps.VclPass}}
sub vcl_pass {
{{.VCLSteps.VclPass}}
}
{{- end}}
# END vcl_pass content

# START vcl_hash content
{{- if .VCLSteps.VclHash}}
sub vcl_hash {
{{.VCLSteps.VclHash}}
}
{{- end}}
# END vcl_hash content

# START vcl_purge content
{{- if .VCLSteps.VclPurge}}
sub vcl_purge {
{{.VCLSteps.VclPurge}}
}
{{- end}}
# END vcl_purge content

# START vcl_miss content
{{- if .VCLSteps.VclMiss}}
sub vcl_miss {
{{.VCLSteps.VclMiss}}
}
{{- end}}
# END vcl_miss content

# START vcl_hit content
{{- if .VCLSteps.VclHit}}
sub vcl_hit {
{{.VCLSteps.VclHit}}
}
{{- end}}
# END vcl_hit content

# START vcl_deliver content
{{- if .VCLSteps.VclDeliver}}
sub vcl_deliver {
{{.VCLSteps.VclDeliver}}
}
{{- end}}
# END vcl_deliver content

# START vcl_synth content
{{- if .VCLSteps.VclSynth}}
sub vcl_synth {
{{.VCLSteps.VclSynth}}
}
{{- end}}
# END vcl_synth content

# START vcl_backend_fetch content
{{- if .VCLSteps.VclBackendFetch}}
sub vcl_backend_fetch {
{{.VCLSteps.VclBackendFetch}}
}
{{- end}}
# END vcl_backend_fetch content

sub vcl_backend_response {
  # Use slash/fellow for storage
  set beresp.storage = storage.fellow;

  # https://www.varnish-software.com/developers/tutorials/avoid-http-to-https-redirect-loops-varnish/#create-cache-variations-based-on-the-x-forwarded-proto-header
  if(beresp.http.Vary && beresp.http.Vary !~ "(?i)X-Forwarded-Proto") {
    set beresp.http.Vary = beresp.http.Vary + ", X-Forwarded-Proto";
  } else {
    set beresp.http.Vary = "X-Forwarded-Proto";
  }

# START vcl_backend_response content
{{- if .VCLSteps.VclBackendResponse}}
{{.VCLSteps.VclBackendResponse}}
{{- end}}
# END vcl_backend_response content
}

# START vcl_backend_error content
{{- if .VCLSteps.VclBackendError}}
sub vcl_backend_error {
{{.VCLSteps.VclBackendError}}
}
{{- end}}
# END vcl_backend_error content
