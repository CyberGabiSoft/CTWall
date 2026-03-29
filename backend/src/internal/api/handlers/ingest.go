package handlers

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"strings"

	"backend/internal/core/ingest"
	"backend/internal/store"

	"backend/internal/sbom"
)

const maxUploadSize = 50 << 20

var readAll = io.ReadAll

// IngestConfig configures ingest handler behavior.
type IngestConfig struct {
	EnqueueWorkers            int
	ComponentAnalysisNotifier interface {
		NotifyWorkers()
	}
}

// IngestHandler handles SBOM uploads.
func IngestHandler(memStore store.Store, cfg IngestConfig) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		logger := slog.Default().With("component", "handler.ingest")
		logger.Debug("ingest request received",
			"method", r.Method,
			"path", r.URL.Path,
			"content_length", r.ContentLength,
		)
		_, activeProject, resolveErr := resolveActiveProjectWithRole(r, memStore, store.ProjectRoleWriter)
		if resolveErr != nil {
			writeProblem(w, r, resolveErr.status, resolveErr.title, resolveErr.detail, resolveErr.err)
			return
		}

		r.Body = http.MaxBytesReader(w, r.Body, maxUploadSize)
		if err := r.ParseMultipartForm(maxUploadSize); err != nil {
			writeProblem(w, r, http.StatusBadRequest, "Invalid Request", "File too big or invalid multipart", err)
			return
		}

		file, header, err := r.FormFile("sbom_file")
		if err != nil {
			writeProblem(w, r, http.StatusBadRequest, "Invalid Request", "Field 'sbom_file' is missing.", err)
			return
		}
		defer file.Close()

		data, err := readAll(file)
		if err != nil {
			writeProblem(w, r, http.StatusInternalServerError, "Internal Error", "Failed to read SBOM file.", err)
			return
		}
		if len(data) == 0 {
			writeProblem(w, r, http.StatusBadRequest, "Invalid Request", "SBOM file is empty.", nil)
			return
		}

		hash := sha256.Sum256(data)
		sha := hex.EncodeToString(hash[:])
		isGzip := isGzipPayload(data)
		logger.Debug("sbom payload read",
			"size_bytes", len(data),
			"sha256", sha,
			"is_gzip", isGzip,
		)

		metadataJSON, err := validateMetadataJSON(r.FormValue("metadataJson"))
		if err != nil {
			writeProblem(w, r, http.StatusBadRequest, "Invalid Request", err.Error(), nil)
			return
		}

		tags, err := normalizeTags(extractTags(r))
		if err != nil {
			writeProblem(w, r, http.StatusBadRequest, "Invalid Request", err.Error(), nil)
			return
		}

		sbomDoc, err := sbom.ParseMaybeGzip(data, isGzip)
		if err != nil {
			writeProblem(w, r, http.StatusBadRequest, "Invalid Request", "SBOM payload is invalid or unsupported.", err)
			return
		}
		derivedType := sbomDoc.Type
		derivedStandard, err := sbom.NormalizeStandard(string(derivedType.Standard))
		if err != nil || derivedStandard == "" {
			writeProblem(w, r, http.StatusBadRequest, "Invalid Request", "SBOM standard is not supported.", err)
			return
		}
		derivedSpec, err := sbom.NormalizeSpecVersion(derivedType.SpecVersion)
		if err != nil {
			writeProblem(w, r, http.StatusBadRequest, "Invalid Request", "SBOM spec version is invalid.", err)
			return
		}
		derivedType = sbom.Type{Standard: derivedStandard, SpecVersion: derivedSpec}

		requestedType, providedType, err := parseSbomTypeField(r.FormValue("sbomType"))
		if err != nil {
			writeProblem(w, r, http.StatusBadRequest, "Invalid Request", err.Error(), nil)
			return
		}
		if providedType && !sbomTypeMatches(requestedType, derivedType) {
			writeProblem(w, r, http.StatusBadRequest, "Invalid Request", "Field 'sbomType' does not match the uploaded SBOM.", nil)
			return
		}

		producer := sbomDoc.Producer
		if producer == "" {
			producer = sbom.ProducerOther
		}
		requestedProducer, providedProducer, err := parseSbomProducerField(r.FormValue("sbomProducer"))
		if err != nil {
			writeProblem(w, r, http.StatusBadRequest, "Invalid Request", err.Error(), nil)
			return
		}
		if providedProducer {
			if producer == sbom.ProducerOther {
				producer = requestedProducer
			} else if !sbomProducerMatches(requestedProducer, producer) {
				writeProblem(w, r, http.StatusBadRequest, "Invalid Request", "Field 'sbomProducer' does not match the uploaded SBOM.", nil)
				return
			}
		}

		sbomMetadataJSON, err := buildSbomMetadataJSON(sbomDoc.Metadata)
		if err != nil {
			writeProblem(w, r, http.StatusBadRequest, "Invalid Request", err.Error(), nil)
			return
		}

		components, err := buildComponentInputs(sbomDoc.Components)
		if err != nil {
			writeProblem(w, r, http.StatusBadRequest, "Invalid Request", "Failed to normalize SBOM components.", err)
			return
		}
		componentsCount := len(components)

		logger.Debug("ingest metadata parsed",
			"sbom_standard", derivedType.Standard,
			"sbom_spec_version", derivedType.SpecVersion,
			"sbom_producer", producer,
			"tags_count", len(tags),
			"metadata_bytes", len(metadataJSON),
			"components_count", componentsCount,
		)

		input, resolveErr := parseIngestInput(r)
		if resolveErr != nil {
			writeProblem(w, r, resolveErr.status, resolveErr.title, resolveErr.detail, resolveErr.err)
			return
		}
		input.sbomStandard = string(derivedType.Standard)
		input.sbomSpecVersion = derivedType.SpecVersion
		if input.productName, err = validateName("product", input.productName, false); err != nil {
			writeProblem(w, r, http.StatusBadRequest, "Invalid Request", err.Error(), nil)
			return
		}
		if input.scopeName, err = validateName("scope", input.scopeName, false); err != nil {
			writeProblem(w, r, http.StatusBadRequest, "Invalid Request", err.Error(), nil)
			return
		}
		if input.testName, err = validateName("test", input.testName, false); err != nil {
			writeProblem(w, r, http.StatusBadRequest, "Invalid Request", err.Error(), nil)
			return
		}
		logger.Debug("ingest names resolved",
			"product_name", input.productName,
			"scope_name", input.scopeName,
			"test_name", input.testName,
		)

		product, scope, test, resolveErr := resolveEntitiesInputForProject(input, activeProject.ID, memStore)
		if resolveErr != nil {
			writeProblem(w, r, resolveErr.status, resolveErr.title, resolveErr.detail, resolveErr.err)
			return
		}

		contentType := sanitizeContentType(header.Header.Get("Content-Type"))
		job, err := memStore.CreateIngestJob(store.IngestRequest{
			ProductID:       &product.ID,
			ScopeID:         &scope.ID,
			TestID:          &test.ID,
			SbomSha256:      sha,
			SbomStandard:    input.sbomStandard,
			SbomSpecVersion: input.sbomSpecVersion,
			SbomProducer:    string(producer),
			Tags:            tags,
			MetadataJSON:    metadataJSON,
			ContentType:     contentType,
			IsGzip:          isGzip,
			ComponentsCount: componentsCount,
		})
		if err != nil {
			writeProblem(w, r, http.StatusInternalServerError, "Internal Error", "Failed to queue ingest.", err)
			return
		}
		logger.Info("ingest queued",
			"job_id", job.ID,
			"status", job.Status,
		)
		updateStage := func(stage string, errorMessage string) error {
			if err := memStore.UpdateIngestJobStage(job.ID, stage, errorMessage); err != nil {
				return err
			}
			logger.Debug("ingest stage updated", "job_id", job.ID, "stage", stage)
			return nil
		}
		if err := updateStage(store.IngestStageValidating, ""); err != nil {
			writeProblem(w, r, http.StatusInternalServerError, "Internal Error", "Failed to update ingest stage.", err)
			return
		}
		if err := memStore.UpdateIngestJobStatus(job.ID, store.IngestStatusProcessing, ""); err != nil {
			writeProblem(w, r, http.StatusInternalServerError, "Internal Error", "Failed to update ingest status.", err)
			return
		}
		logger.Debug("ingest status updated", "job_id", job.ID, "status", store.IngestStatusProcessing)
		if err := updateStage(store.IngestStageParsing, ""); err != nil {
			writeProblem(w, r, http.StatusInternalServerError, "Internal Error", "Failed to update ingest stage.", err)
			return
		}
		if err := updateStage(store.IngestStageAnalyzing, ""); err != nil {
			writeProblem(w, r, http.StatusInternalServerError, "Internal Error", "Failed to update ingest stage.", err)
			return
		}

		processor := ingest.NewProcessor(memStore, logger, ingest.ProcessorConfig{
			EnqueueWorkers: cfg.EnqueueWorkers,
			Notifier:       cfg.ComponentAnalysisNotifier,
		})
		result, err := processor.Process(ingest.ProcessInput{
			JobID:            job.ID,
			TestID:           test.ID,
			SbomSha256:       sha,
			SbomStandard:     input.sbomStandard,
			SbomSpecVersion:  input.sbomSpecVersion,
			SbomProducer:     string(producer),
			SbomFormat:       sbom.FormatString(derivedType),
			Tags:             tags,
			MetadataJSON:     metadataJSON,
			SbomMetadataJSON: sbomMetadataJSON,
			ContentType:      contentType,
			IsGzip:           isGzip,
			ComponentsCount:  componentsCount,
			Components:       components,
			Payload:          data,
		})
		if err != nil {
			if procErr, ok := err.(*ingest.ProcessError); ok {
				switch procErr.Op {
				case ingest.OpUpdateStage:
					writeProblem(w, r, http.StatusInternalServerError, "Internal Error", "Failed to update ingest stage.", procErr.Err)
				case ingest.OpUpdateStatus:
					writeProblem(w, r, http.StatusInternalServerError, "Internal Error", "Failed to update ingest status.", procErr.Err)
				case ingest.OpStoreSbom:
					writeProblem(w, r, http.StatusInternalServerError, "Internal Error", "Failed to store SBOM.", procErr.Err)
				case ingest.OpAddRevision:
					writeProblem(w, r, http.StatusInternalServerError, "Internal Error", "Failed to store revision.", procErr.Err)
				case ingest.OpEnqueueAnalysis:
					writeProblem(w, r, http.StatusInternalServerError, "Internal Error", "Failed to enqueue malware analysis.", procErr.Err)
				default:
					writeProblem(w, r, http.StatusInternalServerError, "Internal Error", "Failed to process ingest.", procErr.Err)
				}
				return
			}
			writeProblem(w, r, http.StatusInternalServerError, "Internal Error", "Failed to process ingest.", err)
			return
		}
		revision := result.Revision
		logger.Info("ingest completed",
			"job_id", job.ID,
			"revision_id", revision.ID,
			"components_count", componentsCount,
		)

		resp := map[string]any{
			"productId":               product.ID,
			"scopeId":                 scope.ID,
			"testId":                  test.ID,
			"revisionId":              revision.ID,
			"sbomSha256":              sha,
			"componentsImportedCount": componentsCount,
			"createdAt":               revision.CreatedAt,
		}

		writeJSON(w, http.StatusCreated, resp)
	}
}

func extractTags(r *http.Request) []string {
	if r.MultipartForm == nil {
		return nil
	}
	values := r.MultipartForm.Value["tags"]
	if len(values) == 0 {
		values = r.MultipartForm.Value["tags[]"]
	}
	trimmed := make([]string, 0, len(values))
	for _, value := range values {
		if tag := strings.TrimSpace(value); tag != "" {
			trimmed = append(trimmed, tag)
		}
	}
	return trimmed
}

func isGzipPayload(data []byte) bool {
	return len(data) > 2 && data[0] == 0x1f && data[1] == 0x8b
}

func sbomTypeMatches(a, b sbom.Type) bool {
	return strings.EqualFold(string(a.Standard), string(b.Standard)) &&
		strings.EqualFold(strings.TrimSpace(a.SpecVersion), strings.TrimSpace(b.SpecVersion))
}

func sbomProducerMatches(a, b sbom.Producer) bool {
	return strings.EqualFold(string(a), string(b))
}

func buildSbomMetadataJSON(metadata sbom.DocumentMetadata) (json.RawMessage, error) {
	raw, err := json.Marshal(metadata)
	if err != nil {
		return nil, err
	}
	// Trim empty metadata.
	if string(raw) == "{}" {
		return nil, nil
	}
	return validateSbomMetadataJSON(raw)
}

func buildComponentInputs(components []sbom.Component) ([]store.ComponentInput, error) {
	if len(components) == 0 {
		return nil, nil
	}
	output := make([]store.ComponentInput, 0, len(components))
	for _, component := range components {
		purl, err := validatePURL(component.PURL)
		if err != nil {
			return nil, store.ErrInvalidPayload
		}
		pkgName := sanitizePlainText(component.Name)
		version := sanitizePlainText(component.Version)
		pkgType := sanitizePlainText(component.Type)
		pkgNamespace := sanitizePlainText(component.Namespace)
		sbomType := sanitizePlainText(component.SbomType)
		publisher := sanitizePlainText(component.Properties.Publisher)
		supplier := sanitizePlainText(component.Properties.Supplier)
		if pkgNamespace == "" {
			pkgNamespace = sanitizePlainText(deriveNamespaceFromPURL(purl))
		}
		if pkgNamespace == "" {
			pkgNamespace = "unknown"
		}

		if purl == "" || pkgName == "" {
			return nil, store.ErrInvalidPayload
		}
		if version == "" {
			version = "unknown"
		}
		if pkgType == "" {
			pkgType = "unknown"
		}
		if sbomType == "" {
			sbomType = "unknown"
		}

		licenses, err := marshalLicenses(component.Licenses)
		if err != nil {
			return nil, err
		}
		properties, err := json.Marshal(component.Properties)
		if err != nil {
			return nil, err
		}
		output = append(output, store.ComponentInput{
			PURL:         purl,
			PkgName:      pkgName,
			Version:      version,
			PkgType:      pkgType,
			PkgNamespace: pkgNamespace,
			SbomType:     sbomType,
			Publisher:    publisher,
			Supplier:     supplier,
			Licenses:     licenses,
			Properties:   properties,
		})
	}
	return output, nil
}

func deriveNamespaceFromPURL(purl string) string {
	clean := strings.TrimSpace(purl)
	if !strings.HasPrefix(clean, "pkg:") {
		return ""
	}
	clean = strings.TrimPrefix(clean, "pkg:")
	clean = strings.SplitN(clean, "?", 2)[0]
	clean = strings.SplitN(clean, "#", 2)[0]
	parts := strings.SplitN(clean, "/", 2)
	if len(parts) < 2 {
		return ""
	}
	rest := strings.SplitN(parts[1], "@", 2)[0]
	segments := strings.Split(rest, "/")
	if len(segments) <= 1 {
		return ""
	}
	return strings.Join(segments[:len(segments)-1], "/")
}

func marshalLicenses(licenses []sbom.License) ([]byte, error) {
	if len(licenses) == 0 {
		return []byte("[]"), nil
	}
	return json.Marshal(licenses)
}
