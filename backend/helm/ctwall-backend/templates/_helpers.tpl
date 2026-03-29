{{/*
Expand the name of the chart.
*/}}
{{- define "ctwall-backend.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Create a default fully qualified app name.
We truncate at 63 chars because some Kubernetes name fields are limited to this (by the DNS naming spec).
If release name contains chart name it will be used as a full name.
*/}}
{{- define "ctwall-backend.fullname" -}}
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
{{- define "ctwall-backend.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Common labels
*/}}
{{- define "ctwall-backend.labels" -}}
helm.sh/chart: {{ include "ctwall-backend.chart" . }}
{{ include "ctwall-backend.selectorLabels" . }}
{{- if .Chart.AppVersion }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
{{- end }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end }}

{{/*
Selector labels
*/}}
{{- define "ctwall-backend.selectorLabels" -}}
app.kubernetes.io/name: {{ include "ctwall-backend.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}

{{/*
Create the name of the service account to use
*/}}
{{- define "ctwall-backend.serviceAccountName" -}}
{{- if .Values.serviceAccount.create }}
{{- default (include "ctwall-backend.fullname" .) .Values.serviceAccount.name }}
{{- else }}
{{- default "default" .Values.serviceAccount.name }}
{{- end }}
{{- end }}

{{/*
Create the name of Secret with runtime env values
*/}}
{{- define "ctwall-backend.secretName" -}}
{{- if .Values.secretEnv.existingSecret }}
{{- .Values.secretEnv.existingSecret }}
{{- else }}
{{- printf "%s-%s" (include "ctwall-backend.fullname" .) .Values.secretEnv.nameSuffix | trunc 63 | trimSuffix "-" }}
{{- end }}
{{- end }}

{{/*
Create PostgreSQL service name
*/}}
{{- define "ctwall-backend.postgresqlServiceName" -}}
{{- printf "%s-postgresql" (include "ctwall-backend.fullname" .) | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Create PostgreSQL PVC name
*/}}
{{- define "ctwall-backend.postgresqlPvcName" -}}
{{- printf "%s-postgresql-data" (include "ctwall-backend.fullname" .) | trunc 63 | trimSuffix "-" }}
{{- end }}
