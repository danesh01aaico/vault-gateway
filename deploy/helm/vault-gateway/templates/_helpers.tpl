{{/*
Expand the name of the chart.
*/}}
{{- define "vault-gateway.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Create a default fully qualified app name.
We truncate at 63 chars because some Kubernetes name fields are limited to this.
*/}}
{{- define "vault-gateway.fullname" -}}
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
{{- define "vault-gateway.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Common labels
*/}}
{{- define "vault-gateway.labels" -}}
helm.sh/chart: {{ include "vault-gateway.chart" . }}
{{ include "vault-gateway.selectorLabels" . }}
{{- if .Chart.AppVersion }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
{{- end }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end }}

{{/*
Selector labels.
Note: `app: vault-gateway` is intentionally included (in addition to the
standard app.kubernetes.io labels) because the NetworkPolicy and the
Bank-Vaults webhook reference this stable label.
*/}}
{{- define "vault-gateway.selectorLabels" -}}
app: vault-gateway
app.kubernetes.io/name: {{ include "vault-gateway.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}

{{/*
Create the name of the service account to use.
*/}}
{{- define "vault-gateway.serviceAccountName" -}}
{{- if .Values.serviceAccount.create }}
{{- default (include "vault-gateway.fullname" .) .Values.serviceAccount.name }}
{{- else }}
{{- default "default" .Values.serviceAccount.name }}
{{- end }}
{{- end }}

{{/*
Resolve the image tag, defaulting to the chart appVersion.
*/}}
{{- define "vault-gateway.imageTag" -}}
{{- default .Chart.AppVersion .Values.image.tag }}
{{- end }}
