{{- define "github-oidc-exchange.name" -}}
github-oidc-exchange
{{- end }}

{{- define "github-oidc-exchange.labels" -}}
app.kubernetes.io/name: {{ include "github-oidc-exchange.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
helm.sh/chart: {{ printf "%s-%s" .Chart.Name (.Chart.Version | replace "+" "_") | quote }}
{{- end }}

{{- define "github-oidc-exchange.selectorLabels" -}}
app.kubernetes.io/name: {{ include "github-oidc-exchange.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}
