{{/*
Expand the name of the chart.
*/}}
{{- define "base.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Create a default fully qualified app name.
We truncate at 63 chars because some Kubernetes name fields are limited to this (by the DNS naming spec).
If release name contains chart name it will be used as a full name.
*/}}
{{- define "base.fullname" -}}
{{- if .Values.fullnameOverride }}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- $name := default .Chart.Name .Values.nameOverride }}
{{- if contains $name .Release.Name }}
{{- .Release.Name | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- printf "%s-%s" .Release.Name $name | trunc 63 | trimSuffix "-" }}
{{- end }}
{{- end }}
{{- end }}

{{/*
Create chart name and version as used by the chart label.
*/}}
{{- define "base.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Common labels
*/}}
{{- define "base.labels" -}}
helm.sh/chart: {{ include "base.chart" . }}
{{ include "base.selectorLabels" . }}
{{- if .Chart.AppVersion }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
{{- end }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end }}

{{/*
Selector labels
*/}}
{{- define "base.selectorLabels" -}}
app.kubernetes.io/name: {{ include "base.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}

{{/*
Create the name of the service account to use
*/}}
{{- define "base.serviceAccountName" -}}
{{- if .Values.serviceAccount.create }}
{{- default (include "base.fullname" .) .Values.serviceAccount.name }}
{{- else }}
{{- default "default" .Values.serviceAccount.name }}
{{- end }}
{{- end }}


{{/* Minibridge configuration */}}
{{- define "minibridge.secrets" -}}
{{- with .Values.minibridge.tls }}
  {{- if .enabled }}
    {{- with .cert.value }}
    minibridge-cert.pem: {{. | quote }}
    {{- end }}
    {{- with .key.value }}
    minibridge-key.pem: {{. | quote }}
    {{- end }}
    {{- with .pass.value }}
    minibridge-key.pass: {{. | b64enc | quote }}
    {{- end }}
    {{- with .clientCA.value }}
    minibridge-client-ca.pem: {{. | quote }}
    {{- end }}
  {{- end }}
{{- end }}

{{- with .Values.minibridge.policer }}
    {{- with .token.value }}
    minibridge-policer-token: {{. | b64enc | quote }}
    {{- end }}
    {{- with .ca.value }}
    minibridge-policer-ca.pem: {{. | quote }}
    {{- end }}
{{- end }}

{{- end }}

{{- define "minibridge.items" -}}
{{- with .Values.minibridge.tls }}
  {{- if .enabled }}
    {{- with .cert.value }}
    - key: minibridge-cert.pem
      path: minibridge-cert.pem
    {{- end }}
    {{- with .key.value }}
    - key: minibridge-key.pem
      path: minibridge-key.pem
    {{- end }}
    {{- with .clientCA.value }}
    - key: minibridge-client-ca.pem
      path: minibridge-client-ca.pem
    {{- end }}
  {{- end }}
{{- end }}

{{- with .Values.minibridge.policer }}
    {{- with .ca.value }}
    - key: minibridge-policer-ca.pem
      path: minibridge-policer-ca.pem
    {{- end }}
{{- end }}
{{- end }}

{{- define "minibridge.env" -}}

{{- with .Values.minibridge.mode }}
- name: MINIBRIDGE_MODE
  value: {{ (eq . "http" ) | ternary "aio" "backend"}}
{{- end }}
{{- with .Values.minibridge.log.level}}
- name: MINIBRIDGE_LOG_LEVEL
  value: {{.}}
{{- end }}

{{- with .Values.minibridge.tls }}
  {{- if  .enabled }}
- name: MINIBRIDGE_CERT
  value: {{ .cert.path | default "/certs/minibrige-cert.pem"}}
- name: MINIBRIDGE_KEY
  value: {{ .key.path | default "/certs/minibrige-key.pem"}}
- name: MINIBRIDGE_KEY_PASS
  valueFrom:
    secretKeyRef:
      name: "{{ .pass.valueFrom.name | default (printf "%s-secrets" (include "base.fullname" .)) }}"
      key: "{{ .pass.valueFrom.key | default "minibridge-key.pass" }}"
    {{- if or .clientCA.value .clientCA.path }}
- name: MINIBRIDGE_CLIENT_CA
  value: {{ .clientCA.path | default "/certs/minibrige-client-ca.pem"}}
    {{- end }}
  {{- end }}
{{- end }}

{{- with .Values.minibridge.policer }}
{{- if .url }}
- name: MINIBRIDGE_POLICER_URL
  value: {{.url}}
  {{- if or .ca.path .ca.value }}
- name: MINIBRIDGE_POLICER_CA
  value: {{ .ca.path | default "/certs/minibrige-key.pem"}}
  {{- end }}
  {{- if or .token.value .token.valueFrom.name }}
- name: MINIBRIDGE_POLICER_TOKEN
  valueFrom:
    secretKeyRef:
      name: "{{ .pass.valueFrom.name | default (printf "%s-secrets" .Release.name) }}"
      key: "{{ .pass.valueFrom.key | default "minibridge-policer-token" }}"
  {{- end }}
{{- end }}
{{- end }}

{{- end }}

