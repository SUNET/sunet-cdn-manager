  # Use slash/fellow for storage
  set beresp.storage = storage.fellow;

  # https://www.varnish-software.com/developers/tutorials/avoid-http-to-https-redirect-loops-varnish/#create-cache-variations-based-on-the-x-forwarded-proto-header
  if (!beresp.http.Vary) {
    set beresp.http.Vary = "X-Forwarded-Proto";
  } elseif (beresp.http.Vary !~ "(?i)X-Forwarded-Proto") {
    set beresp.http.Vary = beresp.http.Vary + ", X-Forwarded-Proto";
  }
