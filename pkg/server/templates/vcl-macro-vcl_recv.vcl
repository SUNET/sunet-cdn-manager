  if (proxy.is_ssl()) {
    {{- if .HTTPSEnabled}}
    set req.http.X-Forwarded-Proto = "https";
    {{- if .HTTPSSelection}}
{{.HTTPSSelection}}
    {{- end}}
    {{- else}}
    return(synth(400,"HTTPS request but no HTTPS origin available."));
    {{- end}}
  } else {
    {{- if .HTTPEnabled}}
    set req.http.X-Forwarded-Proto = "http";
    {{- if .HTTPSelection}}
{{.HTTPSelection}}
    {{- end}}
    {{- else}}
    return(synth(400,"HTTP request but no HTTP origin available."));
    {{- end}}
  }
