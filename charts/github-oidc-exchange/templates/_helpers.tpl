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

{{- define "github-oidc-exchange.validateImageDigest" -}}
{{- $digest := default "" .Values.image.digest -}}
{{- $sentinels := list
  "sha256:0000000000000000000000000000000000000000000000000000000000000000"
  "sha256:1111111111111111111111111111111111111111111111111111111111111111"
  "sha256:2222222222222222222222222222222222222222222222222222222222222222"
  "sha256:3333333333333333333333333333333333333333333333333333333333333333"
  "sha256:4444444444444444444444444444444444444444444444444444444444444444"
  "sha256:5555555555555555555555555555555555555555555555555555555555555555"
  "sha256:6666666666666666666666666666666666666666666666666666666666666666"
  "sha256:7777777777777777777777777777777777777777777777777777777777777777"
  "sha256:8888888888888888888888888888888888888888888888888888888888888888"
  "sha256:9999999999999999999999999999999999999999999999999999999999999999"
  "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
  "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
  "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
  "sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"
  "sha256:eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"
  "sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
-}}
{{- if has $digest $sentinels -}}
{{- fail (printf "image.digest: placeholder/sentinel value %q is not deployable; set image.digest to the immutable sha256 digest from a published release handoff or a verified manifest-preserving mirror" $digest) -}}
{{- end -}}
{{- end }}
