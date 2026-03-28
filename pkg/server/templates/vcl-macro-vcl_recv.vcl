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
