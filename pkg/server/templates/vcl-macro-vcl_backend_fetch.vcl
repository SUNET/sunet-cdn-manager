  # Vinyl retries a fetch once if a reused backend connection closes before
  # any response arrives. haproxy closes the connection that way when a
  # request fails on a reused origin connection and haproxy itself is not
  # allowed to retry it, which is the case for everything except the safe
  # methods GET, HEAD and OPTIONS. The origin may already have acted on such
  # a request, so do not let vinyl repeat it either; the client gets an
  # error and can decide itself.
  #
  # GET, HEAD and OPTIONS do not get retried twice: once haproxy has used
  # its own retry it answers with an error response, which vinyl does not
  # retry. Vinyl's retry then only covers losing the connection to haproxy
  # itself, e.g. an idle timeout or reload.
  if (bereq.method != "GET" && bereq.method != "HEAD" && bereq.method != "OPTIONS") {
    set bereq.retry_connect = false;
  }
