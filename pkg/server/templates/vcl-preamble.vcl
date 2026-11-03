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
  .path = "/haproxy-unix-sockets/haproxy_{{$originGroup.Name}}_https";
}
{{- end}}
{{- if $originGroup.HTTP }}
backend {{$originGroup.Name}}_http {
  .path = "/haproxy-unix-sockets/haproxy_{{$originGroup.Name}}_http";
}
{{- end}}
{{- end}}

sub sunet_cdn_stored_object {
  # Rules that must apply to every object entering the cache, whether
  # from a backend response (vcl_backend_response) or a synthetic
  # response (vcl_backend_error).

  # Use slash/fellow for storage
  set beresp.storage = storage.fellow;

  # https://www.varnish-software.com/developers/tutorials/avoid-http-to-https-redirect-loops-varnish/#create-cache-variations-based-on-the-x-forwarded-proto-header
  if (!beresp.http.Vary) {
    set beresp.http.Vary = "X-Forwarded-Proto";
  } elseif (beresp.http.Vary !~ "(?i)X-Forwarded-Proto") {
    set beresp.http.Vary = beresp.http.Vary + ", X-Forwarded-Proto";
  }

  # Platform-provided object metadata (URL and Host of the backend request),
  # available to tenant VCL as obj.http.Sunet-Cdn-Obj-Url and
  # obj.http.Sunet-Cdn-Obj-Host, e.g. for ban-lurker-friendly bans.
  # Tenant VCL must not modify or remove these.
  # https://vinyl-cache.org/docs/9.1/users-guide/purging.html
  set beresp.http.Sunet-Cdn-Obj-Url = bereq.url;
  set beresp.http.Sunet-Cdn-Obj-Host = bereq.http.host;
}
