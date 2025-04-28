# Javascript libraries
We keep local versions of JS files rather than referring to them at a CDN like
unpkg. This way we are not dependent on external resources.

If adding new versions remember to update ../console.templ to start using them.

We place libraries in the `dist` directory to not have to add more patterns to
`JsFS` in `../components.go` any time we add a new library.

# htmx
Based on https://htmx.org/docs/#installing:
```
htmx_version=2.0.4
curl --create-dirs --output-dir dist/htmx/$htmx_version -LO https://unpkg.com/htmx.org@${htmx_version}/dist/htmx.min.js
```

You can then verify that the downloaded file matches the `integrity=""sha384-[...]"`
hash for the CDN version from the above page with:
```
openssl dgst -sha384 -binary dist/htmx/${htmx_version}/htmx.min.js | openssl base64
```

# _hyperscript
Based on the redirect of the unpkg URL:
```
hyperscript_version=0.9.14
curl --create-dirs --output-dir dist/_hyperscript/$hyperscript_version -LO https://unpkg.com/hyperscript.org@${hyperscript_version}/dist/_hyperscript.min.js
```
