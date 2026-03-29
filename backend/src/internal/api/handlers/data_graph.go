package handlers

import (
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"backend/internal/models"
	"backend/internal/store"

	"backend/internal/sbom"
	"github.com/google/uuid"
)

type dataGraphNode struct {
	ID           string `json:"id"`
	Label        string `json:"label"`
	PURL         string `json:"purl"`
	PkgType      string `json:"pkgType"`
	PkgNamespace string `json:"pkgNamespace,omitempty"`
	Version      string `json:"version,omitempty"`
	IsMalware    bool   `json:"isMalware"`
	MalwareCount int    `json:"malwareCount"`
}

type dataGraphEdge struct {
	From             string `json:"from"`
	To               string `json:"to"`
	RelationshipType string `json:"relationshipType"`
}

type dataGraphChainMetadata struct {
	ProjectID        string    `json:"projectId"`
	ProductID        string    `json:"productId"`
	ProductName      string    `json:"productName"`
	ScopeID          string    `json:"scopeId"`
	ScopeName        string    `json:"scopeName"`
	TestID           string    `json:"testId"`
	TestName         string    `json:"testName"`
	RevisionID       string    `json:"revisionId"`
	SbomStandard     string    `json:"sbomStandard"`
	SbomSpecVersion  string    `json:"sbomSpecVersion"`
	SbomProducer     string    `json:"sbomProducer"`
	GeneratedAt      time.Time `json:"generatedAt"`
	Truncated        bool      `json:"truncated"`
	TruncationReason string    `json:"truncationReason,omitempty"`
	NodeCount        int       `json:"nodeCount"`
	EdgeCount        int       `json:"edgeCount"`
}

type dataGraphChainPayload struct {
	Nodes    []dataGraphNode        `json:"nodes"`
	Edges    []dataGraphEdge        `json:"edges"`
	Metadata dataGraphChainMetadata `json:"metadata"`
}

type dataGraphChainResponse struct {
	Scope     string                `json:"scope"`
	ProjectID string                `json:"projectId"`
	Data      dataGraphChainPayload `json:"data"`
}

type dataGraphMalwareSummary struct {
	Verdict       string     `json:"verdict"`
	FindingsCount int        `json:"findingsCount"`
	Summary       string     `json:"summary,omitempty"`
	ScannedAt     *time.Time `json:"scannedAt,omitempty"`
	ValidUntil    *time.Time `json:"validUntil,omitempty"`
}

type dataGraphComponentDetailsPayload struct {
	Identity        *store.DataGraphComponentRecord      `json:"identity"`
	MalwareSummary  dataGraphMalwareSummary              `json:"malwareSummary"`
	MalwareFindings []store.DataGraphComponentFinding    `json:"malwareFindings"`
	RawFindings     []models.ScanComponentResult         `json:"rawFindings"`
	QueueHistory    []models.ComponentAnalysisQueueItem  `json:"queueHistory"`
	Occurrences     []store.DataGraphComponentOccurrence `json:"occurrences"`
}

type dataGraphComponentDetailsResponse struct {
	Scope      string                           `json:"scope"`
	ProjectID  string                           `json:"projectId"`
	TestID     string                           `json:"testId"`
	RevisionID string                           `json:"revisionId"`
	PURL       string                           `json:"purl"`
	Data       dataGraphComponentDetailsPayload `json:"data"`
}

type dataGraphBuildResult struct {
	Nodes            []dataGraphNode
	Edges            []dataGraphEdge
	Truncated        bool
	TruncationReason string
}

// DataGraphChainHandler returns a dependency chain graph for a selected test/revision.
func DataGraphChainHandler(st store.Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		_, project, resolveErr := resolveActiveProject(r, st)
		if resolveErr != nil {
			writeProblem(w, r, resolveErr.status, resolveErr.title, resolveErr.detail, resolveErr.err)
			return
		}

		testID, err := parseDataGraphTestID(r.URL.Query().Get("testId"))
		if err != nil {
			writeProblem(w, r, http.StatusBadRequest, "Invalid Request", "Invalid testId.", err)
			return
		}
		testEntity, err := st.GetTestInProject(project.ID, testID)
		if err != nil {
			if errors.Is(err, store.ErrNotFound) {
				writeProblem(w, r, http.StatusNotFound, "Not Found", "Test not found.", nil)
				return
			}
			writeProblem(w, r, http.StatusInternalServerError, "Internal Error", "Failed to load test.", err)
			return
		}

		scopeEntity, err := st.GetScopeInProject(project.ID, testEntity.ScopeID)
		if err != nil {
			if errors.Is(err, store.ErrNotFound) {
				writeProblem(w, r, http.StatusNotFound, "Not Found", "Scope not found.", nil)
				return
			}
			writeProblem(w, r, http.StatusInternalServerError, "Internal Error", "Failed to load scope.", err)
			return
		}
		productEntity, err := st.GetProductInProject(project.ID, scopeEntity.ProductID)
		if err != nil {
			if errors.Is(err, store.ErrNotFound) {
				writeProblem(w, r, http.StatusNotFound, "Not Found", "Product not found.", nil)
				return
			}
			writeProblem(w, r, http.StatusInternalServerError, "Internal Error", "Failed to load product.", err)
			return
		}

		maxNodes, err := parseDataGraphMaxNodes(r.URL.Query().Get("maxNodes"))
		if err != nil {
			writeProblem(w, r, http.StatusBadRequest, "Invalid Request", "Invalid maxNodes. Value must be >= 1.", err)
			return
		}

		producer, err := parseDataGraphProducer(r.URL.Query().Get("producer"))
		if err != nil {
			writeProblem(w, r, http.StatusBadRequest, "Invalid Request", "Invalid producer. Allowed: syft, trivy, grype, other.", err)
			return
		}

		revisionEntity, err := resolveDataGraphRevision(st, project.ID, testID, r.URL.Query().Get("revisionId"), producer)
		if err != nil {
			if errors.Is(err, store.ErrNotFound) {
				writeProblem(w, r, http.StatusNotFound, "Not Found", "Revision not found.", nil)
				return
			}
			if errors.Is(err, store.ErrInvalidPayload) {
				writeProblem(w, r, http.StatusBadRequest, "Invalid Request", "Invalid revisionId.", err)
				return
			}
			writeProblem(w, r, http.StatusInternalServerError, "Internal Error", "Failed to resolve revision.", err)
			return
		}

		sbomObject, err := st.GetSbomBySHA(revisionEntity.SbomSha256)
		if err != nil {
			if errors.Is(err, store.ErrNotFound) {
				writeProblem(w, r, http.StatusNotFound, "Not Found", "SBOM for selected revision not found.", nil)
				return
			}
			writeProblem(w, r, http.StatusInternalServerError, "Internal Error", "Failed to load SBOM for selected revision.", err)
			return
		}

		document, err := sbom.ParseMaybeGzip(sbomObject.Bytes, sbomObject.IsGzip)
		if err != nil {
			writeProblem(w, r, http.StatusInternalServerError, "Internal Error", "Failed to parse selected SBOM.", err)
			return
		}

		graph := buildDataGraphChain(document, maxNodes)
		purls := make([]string, 0, len(graph.Nodes))
		for _, node := range graph.Nodes {
			if strings.TrimSpace(node.PURL) != "" {
				purls = append(purls, node.PURL)
			}
		}
		malwareCounts, err := st.ListDataGraphRevisionMalwareCounts(project.ID, testID, revisionEntity.ID, purls)
		if err != nil {
			writeProblem(w, r, http.StatusInternalServerError, "Internal Error", "Failed to resolve malware status for graph nodes.", err)
			return
		}
		for idx := range graph.Nodes {
			count := malwareCounts[graph.Nodes[idx].PURL]
			graph.Nodes[idx].MalwareCount = count
			graph.Nodes[idx].IsMalware = count > 0
		}

		now := time.Now().UTC()
		payload := dataGraphChainResponse{
			Scope:     "project",
			ProjectID: project.ID.String(),
			Data: dataGraphChainPayload{
				Nodes: graph.Nodes,
				Edges: graph.Edges,
				Metadata: dataGraphChainMetadata{
					ProjectID:        project.ID.String(),
					ProductID:        productEntity.ID.String(),
					ProductName:      productEntity.Name,
					ScopeID:          scopeEntity.ID.String(),
					ScopeName:        scopeEntity.Name,
					TestID:           testEntity.ID.String(),
					TestName:         testEntity.Name,
					RevisionID:       revisionEntity.ID.String(),
					SbomStandard:     testEntity.SbomStandard,
					SbomSpecVersion:  testEntity.SbomSpecVersion,
					SbomProducer:     revisionEntity.SbomProducer,
					GeneratedAt:      now,
					Truncated:        graph.Truncated,
					TruncationReason: graph.TruncationReason,
					NodeCount:        len(graph.Nodes),
					EdgeCount:        len(graph.Edges),
				},
			},
		}
		writeJSON(w, http.StatusOK, payload)
	}
}

// DataGraphComponentDetailsHandler returns full component details for one graph node.
func DataGraphComponentDetailsHandler(st store.Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		_, project, resolveErr := resolveActiveProject(r, st)
		if resolveErr != nil {
			writeProblem(w, r, resolveErr.status, resolveErr.title, resolveErr.detail, resolveErr.err)
			return
		}

		testID, err := parseDataGraphTestID(r.URL.Query().Get("testId"))
		if err != nil {
			writeProblem(w, r, http.StatusBadRequest, "Invalid Request", "Invalid testId.", err)
			return
		}
		if _, err := st.GetTestInProject(project.ID, testID); err != nil {
			if errors.Is(err, store.ErrNotFound) {
				writeProblem(w, r, http.StatusNotFound, "Not Found", "Test not found.", nil)
				return
			}
			writeProblem(w, r, http.StatusInternalServerError, "Internal Error", "Failed to load test.", err)
			return
		}

		componentPURL, err := validatePURL(r.URL.Query().Get("purl"))
		if err != nil {
			writeProblem(w, r, http.StatusBadRequest, "Invalid Request", "Invalid purl.", err)
			return
		}

		revisionEntity, err := resolveDataGraphRevision(st, project.ID, testID, r.URL.Query().Get("revisionId"), "")
		if err != nil {
			if errors.Is(err, store.ErrNotFound) {
				writeProblem(w, r, http.StatusNotFound, "Not Found", "Revision not found.", nil)
				return
			}
			if errors.Is(err, store.ErrInvalidPayload) {
				writeProblem(w, r, http.StatusBadRequest, "Invalid Request", "Invalid revisionId.", err)
				return
			}
			writeProblem(w, r, http.StatusInternalServerError, "Internal Error", "Failed to resolve revision.", err)
			return
		}

		identity, err := st.GetDataGraphComponentByPURL(project.ID, testID, revisionEntity.ID, componentPURL)
		if err != nil {
			if errors.Is(err, store.ErrNotFound) {
				writeProblem(w, r, http.StatusNotFound, "Not Found", "Component not found in selected revision.", nil)
				return
			}
			if errors.Is(err, store.ErrInvalidPayload) {
				writeProblem(w, r, http.StatusBadRequest, "Invalid Request", "Invalid component query.", err)
				return
			}
			writeProblem(w, r, http.StatusInternalServerError, "Internal Error", "Failed to load component details.", err)
			return
		}

		analysisResults, err := st.ListAnalysisResultsForComponentMatch(componentPURL)
		if err != nil && !errors.Is(err, store.ErrNotFound) {
			writeProblem(w, r, http.StatusInternalServerError, "Internal Error", "Failed to load malware summary.", err)
			return
		}
		malwareSummary := buildDataGraphMalwareSummary(analysisResults, componentPURL)

		findings, err := st.ListDataGraphRevisionComponentFindings(
			project.ID,
			testID,
			revisionEntity.ID,
			componentPURL,
			store.DefaultDataGraphRowsLimit,
		)
		if err != nil {
			writeProblem(w, r, http.StatusInternalServerError, "Internal Error", "Failed to load malware findings.", err)
			return
		}

		rawFindings, err := st.ListScanComponentResults(componentPURL, nil, store.DefaultDataGraphRowsLimit, 0)
		if err != nil {
			writeProblem(w, r, http.StatusInternalServerError, "Internal Error", "Failed to load raw findings.", err)
			return
		}

		queueHistory, err := st.ListComponentAnalysisQueue(store.ComponentAnalysisQueueFilter{
			ComponentPURL: componentPURL,
			Limit:         store.DefaultDataGraphRowsLimit,
			Offset:        0,
		})
		if err != nil {
			writeProblem(w, r, http.StatusInternalServerError, "Internal Error", "Failed to load analysis queue history.", err)
			return
		}

		occurrences, err := st.ListDataGraphProjectOccurrencesByPURL(project.ID, componentPURL, store.DefaultDataGraphRowsLimit)
		if err != nil {
			writeProblem(w, r, http.StatusInternalServerError, "Internal Error", "Failed to load component occurrences.", err)
			return
		}

		writeJSON(w, http.StatusOK, dataGraphComponentDetailsResponse{
			Scope:      "project",
			ProjectID:  project.ID.String(),
			TestID:     testID.String(),
			RevisionID: revisionEntity.ID.String(),
			PURL:       componentPURL,
			Data: dataGraphComponentDetailsPayload{
				Identity:        identity,
				MalwareSummary:  malwareSummary,
				MalwareFindings: findings,
				RawFindings:     rawFindings,
				QueueHistory:    queueHistory,
				Occurrences:     occurrences,
			},
		})
	}
}

func parseDataGraphTestID(raw string) (uuid.UUID, error) {
	value := strings.TrimSpace(raw)
	if value == "" {
		return uuid.Nil, store.ErrInvalidPayload
	}
	testID, err := uuid.Parse(value)
	if err != nil {
		return uuid.Nil, err
	}
	return testID, nil
}

func parseDataGraphProducer(raw string) (string, error) {
	value := strings.TrimSpace(raw)
	if value == "" {
		return "", nil
	}
	normalized, err := sbom.NormalizeProducer(value)
	if err != nil || normalized == "" {
		return "", store.ErrInvalidPayload
	}
	return string(normalized), nil
}

func parseDataGraphMaxNodes(raw string) (int, error) {
	value := strings.TrimSpace(raw)
	if value == "" {
		return store.DefaultDataGraphMaxNodes, nil
	}
	parsed, err := strconv.Atoi(value)
	if err != nil {
		return 0, err
	}
	if parsed < 1 {
		return 0, store.ErrInvalidPayload
	}
	if parsed > store.MaxDataGraphMaxNodes {
		return store.MaxDataGraphMaxNodes, nil
	}
	return parsed, nil
}

func resolveDataGraphRevision(
	st store.Store,
	projectID, testID uuid.UUID,
	rawRevisionID string,
	producer string,
) (*models.TestRevision, error) {
	revisionIDRaw := strings.TrimSpace(rawRevisionID)
	if revisionIDRaw != "" {
		revisionID, err := uuid.Parse(revisionIDRaw)
		if err != nil {
			return nil, store.ErrInvalidPayload
		}
		revision, err := st.GetRevisionInProject(projectID, revisionID)
		if err != nil {
			return nil, err
		}
		if revision.TestID != testID {
			return nil, store.ErrNotFound
		}
		return revision, nil
	}

	revisions, err := st.ListRevisions(testID)
	if err != nil {
		return nil, err
	}
	if len(revisions) == 0 {
		return nil, store.ErrNotFound
	}

	if producer != "" {
		for idx := len(revisions) - 1; idx >= 0; idx-- {
			if strings.EqualFold(strings.TrimSpace(revisions[idx].SbomProducer), producer) {
				revision := revisions[idx]
				return &revision, nil
			}
		}
		return nil, store.ErrNotFound
	}

	for idx := len(revisions) - 1; idx >= 0; idx-- {
		if revisions[idx].IsActive {
			revision := revisions[idx]
			return &revision, nil
		}
	}

	latest := revisions[len(revisions)-1]
	return &latest, nil
}

func buildDataGraphChain(document *sbom.Document, maxNodes int) dataGraphBuildResult {
	if document == nil {
		return dataGraphBuildResult{
			Nodes: make([]dataGraphNode, 0),
			Edges: make([]dataGraphEdge, 0),
		}
	}

	nodesByID := make(map[string]dataGraphNode, len(document.Components))
	nodeOrder := make([]string, 0, len(document.Components))
	aliases := make(map[string]string, len(document.Components)*3)

	registerAlias := func(alias, nodeID string) {
		key := strings.TrimSpace(alias)
		if key == "" || nodeID == "" {
			return
		}
		aliases[key] = nodeID
	}

	for _, component := range document.Components {
		nodeID := dataGraphNodeID(component)
		if nodeID == "" {
			continue
		}
		if _, exists := nodesByID[nodeID]; !exists {
			label := strings.TrimSpace(component.Name)
			version := strings.TrimSpace(component.Version)
			if label == "" {
				label = nodeID
			}
			if version != "" && version != "unknown" {
				label = fmt.Sprintf("%s@%s", label, version)
			}
			nodesByID[nodeID] = dataGraphNode{
				ID:           nodeID,
				Label:        label,
				PURL:         nodeID,
				PkgType:      strings.TrimSpace(component.Type),
				PkgNamespace: strings.TrimSpace(component.Namespace),
				Version:      version,
			}
			nodeOrder = append(nodeOrder, nodeID)
		}
		registerAlias(component.PURL, nodeID)
		registerAlias(sbom.NormalizePURL(component.PURL), nodeID)
		registerAlias(component.Properties.BomRef, nodeID)
		registerAlias(component.Properties.SpdxID, nodeID)
	}

	edgeSeen := make(map[string]struct{})
	edges := make([]dataGraphEdge, 0, len(document.Components))
	for _, component := range document.Components {
		fromID := dataGraphNodeID(component)
		if fromID == "" {
			continue
		}
		for _, relation := range component.Properties.Relationships {
			targetID, ok := resolveDataGraphAlias(relation.Target, aliases)
			if !ok || targetID == "" || targetID == fromID {
				continue
			}
			relationshipType := strings.ToUpper(strings.TrimSpace(relation.Type))
			if relationshipType == "" {
				relationshipType = "DEPENDS_ON"
			}
			key := fromID + "\x00" + targetID + "\x00" + relationshipType
			if _, exists := edgeSeen[key]; exists {
				continue
			}
			edgeSeen[key] = struct{}{}
			edges = append(edges, dataGraphEdge{
				From:             fromID,
				To:               targetID,
				RelationshipType: relationshipType,
			})
		}
	}

	truncated := false
	truncationReason := ""
	kept := make(map[string]struct{}, len(nodeOrder))
	if len(nodeOrder) > maxNodes {
		truncated = true
		truncationReason = fmt.Sprintf("Node limit exceeded. Returned %d of %d nodes.", maxNodes, len(nodeOrder))
		nodeOrder = nodeOrder[:maxNodes]
	}
	nodes := make([]dataGraphNode, 0, len(nodeOrder))
	for _, nodeID := range nodeOrder {
		kept[nodeID] = struct{}{}
		nodes = append(nodes, nodesByID[nodeID])
	}

	if truncated {
		filteredEdges := make([]dataGraphEdge, 0, len(edges))
		for _, edge := range edges {
			if _, ok := kept[edge.From]; !ok {
				continue
			}
			if _, ok := kept[edge.To]; !ok {
				continue
			}
			filteredEdges = append(filteredEdges, edge)
		}
		edges = filteredEdges
	}

	return dataGraphBuildResult{
		Nodes:            nodes,
		Edges:            edges,
		Truncated:        truncated,
		TruncationReason: truncationReason,
	}
}

func dataGraphNodeID(component sbom.Component) string {
	purl := strings.TrimSpace(component.PURL)
	if purl != "" {
		return sbom.NormalizePURL(purl)
	}
	if bomRef := strings.TrimSpace(component.Properties.BomRef); bomRef != "" {
		return bomRef
	}
	if spdxID := strings.TrimSpace(component.Properties.SpdxID); spdxID != "" {
		return spdxID
	}
	return ""
}

func resolveDataGraphAlias(target string, aliases map[string]string) (string, bool) {
	clean := strings.TrimSpace(target)
	if clean == "" {
		return "", false
	}
	if resolved, ok := aliases[clean]; ok {
		return resolved, true
	}
	if strings.HasPrefix(clean, "pkg:") {
		normalized := sbom.NormalizePURL(clean)
		if resolved, ok := aliases[normalized]; ok {
			return resolved, true
		}
	}
	return "", false
}

func buildDataGraphMalwareSummary(results []models.AnalysisResult, componentPURL string) dataGraphMalwareSummary {
	summary := dataGraphMalwareSummary{Verdict: "UNKNOWN"}
	if len(results) == 0 {
		return summary
	}

	normalized := sbom.NormalizePURL(componentPURL)
	selected := results[0]
	for _, result := range results {
		if sbom.NormalizePURL(result.ComponentPURL) == normalized {
			selected = result
			break
		}
	}

	summary.Verdict = strings.ToUpper(strings.TrimSpace(selected.Verdict))
	if summary.Verdict == "" {
		summary.Verdict = "UNKNOWN"
	}
	summary.FindingsCount = selected.FindingsCount
	summary.Summary = selected.Summary
	scannedAt := selected.ScannedAt.UTC()
	summary.ScannedAt = &scannedAt
	if selected.ValidUntil != nil {
		validUntil := selected.ValidUntil.UTC()
		summary.ValidUntil = &validUntil
	}
	return summary
}
