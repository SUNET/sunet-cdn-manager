#SUNET-CDN-MANAGER preamble

sub vcl_recv {
  #SUNET-CDN-MANAGER vcl_recv
  # The usage of the proxy module is possible because haproxy is configured
  # to set PROXY SSL headers for us.
  if (proxy.is_ssl()) {
    std.syslog(180, "vcl_recv: this is https");
  } else {
    std.syslog(180, "vcl_recv: this is http");
  }
}

sub vcl_pipe {
  #SUNET-CDN-MANAGER vcl_pipe
}

sub vcl_pass {
  #SUNET-CDN-MANAGER vcl_pass
}

sub vcl_hash {
  #SUNET-CDN-MANAGER vcl_hash
}

sub vcl_purge {
  #SUNET-CDN-MANAGER vcl_purge
}

sub vcl_miss {
  #SUNET-CDN-MANAGER vcl_miss
}

sub vcl_hit {
  #SUNET-CDN-MANAGER vcl_hit
}

sub vcl_deliver {
  #SUNET-CDN-MANAGER vcl_deliver
}

sub vcl_synth {
  #SUNET-CDN-MANAGER vcl_synth
}

sub vcl_backend_fetch {
  #SUNET-CDN-MANAGER vcl_backend_fetch
}

sub vcl_backend_response {
  #SUNET-CDN-MANAGER vcl_backend_response
}

sub vcl_backend_error {
  #SUNET-CDN-MANAGER vcl_backend_error
}
