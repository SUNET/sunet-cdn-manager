# How to fetch the htmx .js file
Based on https://htmx.org/docs/#installing:
```
curl -LO https://unpkg.com/htmx.org@2.0.4/dist/htmx.min.js
```

You can then verify that the downloaded file matches the `integrity=""sha384-[...]"`
hash for the CDN version from the above page with:
```
openssl dgst -sha384 -binary htmx.min.js | openssl base64
```
