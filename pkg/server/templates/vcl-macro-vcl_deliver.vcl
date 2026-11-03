  # Remove X-Forwarded-Proto from the Vary header sent to the client.
  #
  # Our vcl_backend_response adds X-Forwarded-Proto to Vary so HTTP and HTTPS
  # are cached as separate variants of the same object (a single PURGE still
  # clears both). That is an internal detail: clients never send this header and
  # already distinguish schemes by URL. It must stay in the stored object's Vary,
  # so it is only stripped here rather than in vcl_backend_response, where it
  # would affect the cached object.
  #
  # Example: "User-Agent, X-Forwarded-Proto, Accept-Encoding"
  #       -> "User-Agent, Accept-Encoding"
  if (resp.http.Vary) {
    # Remove the X-Forwarded-Proto token:
    # * Case-insensitive.
    # * The match must start at the beginning of the string or at a comma
    #   (that comma is consumed).
    # * Any whitespace surrounding "X-Forwarded-Proto" is consumed.
    # * The next character must be a comma or the end of the string. The
    #   comma is not consumed since it is only checked with a positive
    #   lookahead, so the remaining tokens stay comma-separated. This also
    #   ensures only the whole token matches.
    set resp.http.Vary = regsuball(resp.http.Vary, "(?i)(^|,)\s*X-Forwarded-Proto\s*(?=,|$)", "");
    # If the token was first in the list, no comma preceded it, so a leading
    # comma is left behind. Remove it including surrounding whitespace.
    set resp.http.Vary = regsub(resp.http.Vary, "^\s*,\s*", "");
    # If X-Forwarded-Proto was the only token the header is now empty or
    # whitespace. Remove it entirely rather than send an empty Vary.
    if (resp.http.Vary ~ "^\s*$") {
      unset resp.http.Vary;
    }
  }
