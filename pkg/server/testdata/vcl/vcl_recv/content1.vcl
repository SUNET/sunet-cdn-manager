# The usage of the proxy module is possible because haproxy is configured
# to set PROXY SSL headers for us.
if (proxy.is_ssl()) {
  std.syslog(180, "vcl_recv: this is https");
} else {
  std.syslog(180, "vcl_recv: this is http");
}
