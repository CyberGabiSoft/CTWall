package sbom

import (
	"bytes"
	"compress/gzip"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"regexp"
	"strings"
)

type Standard string

type Producer string

const (
	StandardCycloneDX Standard = "cyclonedx"
	StandardSPDX      Standard = "spdx"
	StandardSWID      Standard = "swid"
)

const (
	ProducerTrivy Producer = "trivy"
	ProducerSyft  Producer = "syft"
	ProducerGrype Producer = "grype"
	ProducerOther Producer = "other"
)

var specVersionPattern = regexp.MustCompile(`^(unknown|\d+(\.\d+){0,2})$`)

// Type represents the SBOM standard and its specification version.
type Type struct {
	Standard    Standard `json:"standard"`
	SpecVersion string   `json:"specVersion"`
}

// DocumentMetadata stores SBOM-level metadata.
type DocumentMetadata struct {
	Timestamp string   `json:"timestamp,omitempty"`
	Authors   []string `json:"authors,omitempty"`
	Supplier  string   `json:"supplier,omitempty"`
	ToolNames []string `json:"toolNames,omitempty"`
}

// Document represents a parsed SBOM payload.
type Document struct {
	Type       Type             `json:"type"`
	Producer   Producer         `json:"producer"`
	Metadata   DocumentMetadata `json:"metadata"`
	Components []Component      `json:"components"`
}

// Component represents a normalized SBOM component.
type Component struct {
	Name       string              `json:"name"`
	Version    string              `json:"version"`
	PURL       string              `json:"purl"`
	Type       string              `json:"type"`
	SbomType   string              `json:"sbomType,omitempty"`
	Namespace  string              `json:"namespace,omitempty"`
	Licenses   []License           `json:"licenses,omitempty"`
	Properties ComponentProperties `json:"properties,omitempty"`
	Original   json.RawMessage     `json:"original,omitempty"`
}

// License holds normalized license information.
type License struct {
	ID         string `json:"id,omitempty"`
	Name       string `json:"name,omitempty"`
	Expression string `json:"expression,omitempty"`
	URL        string `json:"url,omitempty"`
	Source     string `json:"source,omitempty"`
}

// Property represents a scanner-specific property key/value.
type Property struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

// Hash represents a component hash entry.
type Hash struct {
	Alg     string `json:"alg"`
	Content string `json:"content"`
}

// Relationship stores dependency relationships for a component.
type Relationship struct {
	Type   string `json:"type"`
	Target string `json:"target"`
}

// ExternalRef is an SPDX external reference.
type ExternalRef struct {
	Category string `json:"category,omitempty"`
	Type     string `json:"type,omitempty"`
	Locator  string `json:"locator,omitempty"`
}

// ComponentProperties stores additional SBOM metadata for a component.
type ComponentProperties struct {
	Supplier          string         `json:"supplier,omitempty"`
	Publisher         string         `json:"publisher,omitempty"`
	Hashes            []Hash         `json:"hashes,omitempty"`
	Relationships     []Relationship `json:"relationships,omitempty"`
	ExternalRefs      []ExternalRef  `json:"externalRefs,omitempty"`
	BomRef            string         `json:"bomRef,omitempty"`
	SpdxID            string         `json:"spdxId,omitempty"`
	ScannerProperties []Property     `json:"scannerProperties,omitempty"`
}

// NormalizeStandard validates and normalizes SBOM standard values.
func NormalizeStandard(value string) (Standard, error) {
	clean := strings.ToLower(strings.TrimSpace(value))
	switch Standard(clean) {
	case StandardCycloneDX, StandardSPDX, StandardSWID:
		return Standard(clean), nil
	case "":
		return "", nil
	default:
		return "", fmt.Errorf("invalid sbom standard: %s", value)
	}
}

// NormalizeProducer validates and normalizes SBOM producer values.
func NormalizeProducer(value string) (Producer, error) {
	clean := strings.ToLower(strings.TrimSpace(value))
	switch Producer(clean) {
	case ProducerTrivy, ProducerSyft, ProducerGrype, ProducerOther:
		return Producer(clean), nil
	case "":
		return "", nil
	default:
		return "", fmt.Errorf("invalid sbom producer: %s", value)
	}
}

// NormalizeSpecVersion validates the SBOM spec version.
func NormalizeSpecVersion(value string) (string, error) {
	clean := strings.TrimSpace(value)
	if clean == "" {
		return "unknown", nil
	}
	if !specVersionPattern.MatchString(clean) {
		return "", fmt.Errorf("invalid sbom spec version: %s", value)
	}
	return clean, nil
}

// FormatString returns a canonical format string for storage.
func FormatString(t Type) string {
	standard := strings.ToLower(strings.TrimSpace(string(t.Standard)))
	if standard == "" {
		return "unknown"
	}
	spec := strings.TrimSpace(t.SpecVersion)
	if spec == "" {
		spec = "unknown"
	}
	return fmt.Sprintf("%s-json@%s", standard, spec)
}

// NormalizePayload inflates gzip payloads if needed.
func NormalizePayload(data []byte, isGzip bool) ([]byte, error) {
	if !isGzip {
		return data, nil
	}
	reader, err := gzip.NewReader(bytes.NewReader(data))
	if err != nil {
		return nil, err
	}
	defer reader.Close()
	return ioReadAll(reader)
}

// ParseMaybeGzip parses an SBOM payload, optionally gzipped.
func ParseMaybeGzip(data []byte, isGzip bool) (*Document, error) {
	payload, err := NormalizePayload(data, isGzip)
	if err != nil {
		return nil, err
	}
	return Parse(payload)
}

// Parse parses a JSON SBOM payload into a normalized Document.
func Parse(data []byte) (*Document, error) {
	var root map[string]json.RawMessage
	if err := json.Unmarshal(data, &root); err != nil {
		return nil, err
	}

	if _, ok := root["bomFormat"]; ok {
		return parseCycloneDX(root)
	}
	if _, ok := root["spdxVersion"]; ok {
		return parseSPDX(root)
	}
	if _, ok := root["tagId"]; ok {
		return parseSWID(root)
	}
	return nil, errors.New("unsupported sbom format")
}

func parseCycloneDX(root map[string]json.RawMessage) (*Document, error) {
	var specVersion string
	_ = json.Unmarshal(root["specVersion"], &specVersion)
	normalizedSpec, err := NormalizeSpecVersion(specVersion)
	if err != nil {
		normalizedSpec = "unknown"
	}

	metadata, toolCandidates := parseCycloneDXMetadata(root["metadata"])

	var componentsRaw []json.RawMessage
	_ = json.Unmarshal(root["components"], &componentsRaw)

	dependencies := make(map[string][]string)
	var deps []struct {
		Ref       string   `json:"ref"`
		DependsOn []string `json:"dependsOn"`
	}
	if err := json.Unmarshal(root["dependencies"], &deps); err == nil {
		for _, dep := range deps {
			if dep.Ref == "" {
				continue
			}
			dependencies[dep.Ref] = dep.DependsOn
		}
	}

	components := make([]Component, 0, len(componentsRaw))
	for _, raw := range componentsRaw {
		component, err := parseCycloneDXComponent(raw, dependencies)
		if err != nil {
			return nil, err
		}
		if component.PURL != "" {
			component.PURL = NormalizePURL(component.PURL)
		}
		components = append(components, component)
	}

	producer := detectProducer(toolCandidates)

	return &Document{
		Type: Type{
			Standard:    StandardCycloneDX,
			SpecVersion: normalizedSpec,
		},
		Producer:   producer,
		Metadata:   metadata,
		Components: components,
	}, nil
}

func parseCycloneDXMetadata(raw json.RawMessage) (DocumentMetadata, []string) {
	meta := DocumentMetadata{}
	candidates := make([]string, 0)
	if len(raw) == 0 {
		return meta, candidates
	}
	var metaRaw map[string]json.RawMessage
	if err := json.Unmarshal(raw, &metaRaw); err != nil {
		return meta, candidates
	}
	_ = json.Unmarshal(metaRaw["timestamp"], &meta.Timestamp)

	if toolRaw, ok := metaRaw["tools"]; ok {
		toolNames, authors := parseCycloneDXTools(toolRaw)
		meta.ToolNames = append(meta.ToolNames, toolNames...)
		meta.Authors = append(meta.Authors, authors...)
		candidates = append(candidates, toolNames...)
		candidates = append(candidates, authors...)
	}

	if componentRaw, ok := metaRaw["component"]; ok {
		if supplier := parseCycloneDXSupplier(componentRaw); supplier != "" {
			meta.Supplier = supplier
		}
	}

	return meta, candidates
}

func parseCycloneDXTools(raw json.RawMessage) ([]string, []string) {
	names := make([]string, 0)
	authors := make([]string, 0)
	var toolWrapper struct {
		Components []struct {
			Name         string `json:"name"`
			Author       string `json:"author"`
			Manufacturer struct {
				Name string `json:"name"`
			} `json:"manufacturer"`
		} `json:"components"`
	}
	if err := json.Unmarshal(raw, &toolWrapper); err == nil && len(toolWrapper.Components) > 0 {
		for _, tool := range toolWrapper.Components {
			if tool.Name != "" {
				names = append(names, tool.Name)
			}
			if tool.Author != "" {
				authors = append(authors, tool.Author)
			}
			if tool.Manufacturer.Name != "" {
				authors = append(authors, tool.Manufacturer.Name)
			}
		}
		return names, authors
	}

	var tools []struct {
		Name         string `json:"name"`
		Author       string `json:"author"`
		Manufacturer struct {
			Name string `json:"name"`
		} `json:"manufacturer"`
	}
	if err := json.Unmarshal(raw, &tools); err == nil {
		for _, tool := range tools {
			if tool.Name != "" {
				names = append(names, tool.Name)
			}
			if tool.Author != "" {
				authors = append(authors, tool.Author)
			}
			if tool.Manufacturer.Name != "" {
				authors = append(authors, tool.Manufacturer.Name)
			}
		}
	}
	return names, authors
}

func parseCycloneDXSupplier(raw json.RawMessage) string {
	var component map[string]json.RawMessage
	if err := json.Unmarshal(raw, &component); err != nil {
		return ""
	}
	if supplierRaw, ok := component["supplier"]; ok {
		var supplier struct {
			Name string `json:"name"`
		}
		if err := json.Unmarshal(supplierRaw, &supplier); err == nil && supplier.Name != "" {
			return supplier.Name
		}
		var supplierText string
		if err := json.Unmarshal(supplierRaw, &supplierText); err == nil {
			return supplierText
		}
	}
	if publisherRaw, ok := component["publisher"]; ok {
		var publisher string
		if err := json.Unmarshal(publisherRaw, &publisher); err == nil {
			return publisher
		}
	}
	return ""
}

func parseCycloneDXComponent(raw json.RawMessage, dependencies map[string][]string) (Component, error) {
	component := Component{Original: raw}
	var data map[string]json.RawMessage
	if err := json.Unmarshal(raw, &data); err != nil {
		return component, err
	}

	component.Name = rawString(data["name"])
	component.Version = rawString(data["version"])
	component.Namespace = rawString(data["group"])
	component.SbomType = strings.ToLower(rawString(data["type"]))
	component.PURL = rawString(data["purl"])
	bomRef := rawString(data["bom-ref"])

	properties := parseProperties(data["properties"])
	packageType := derivePackageType(properties)
	if packageType != "" {
		component.Type = packageType
	}

	if component.PURL == "" && strings.HasPrefix(bomRef, "pkg:") {
		component.PURL = bomRef
	}
	if component.Version == "" {
		component.Version = parsePURLVersion(component.PURL)
	}
	if component.Version == "" {
		component.Version = "unknown"
	}
	identifier := component.Name
	if identifier == "" {
		_, _, name := parsePURL(component.PURL)
		identifier = name
	}
	if identifier == "" && bomRef != "" {
		identifier = bomRef
	}
	if identifier == "" {
		identifier = "unknown"
	}
	if component.PURL == "" {
		component.PURL = buildGenericPURL(identifier, component.Version)
	}
	if component.Name == "" {
		component.Name = identifier
	}
	if component.Namespace == "" {
		_, namespace, _ := parsePURL(component.PURL)
		component.Namespace = namespace
	}
	if component.Type == "" {
		pkgType, _, _ := parsePURL(component.PURL)
		component.Type = pkgType
	}
	if component.Type == "" {
		component.Type = component.SbomType
	}
	if component.Type == "" {
		component.Type = "unknown"
	}
	if component.SbomType == "" {
		component.SbomType = "unknown"
	}

	component.Licenses = parseCycloneDXLicenses(data["licenses"])

	supplier := parseSupplierField(data["supplier"])
	publisher := rawString(data["publisher"])

	hashes := parseHashes(data["hashes"])
	relationships := buildDependencyRelationships(bomRef, component.PURL, dependencies)

	component.Properties = ComponentProperties{
		Supplier:          supplier,
		Publisher:         publisher,
		Hashes:            hashes,
		Relationships:     relationships,
		BomRef:            bomRef,
		ScannerProperties: properties,
	}

	return component, nil
}

func parseSPDX(root map[string]json.RawMessage) (*Document, error) {
	var spdxVersion string
	_ = json.Unmarshal(root["spdxVersion"], &spdxVersion)
	normalizedSpec := parseSpdxSpecVersion(spdxVersion)
	if normalizedSpec == "" {
		normalizedSpec = "unknown"
	}
	if spec, err := NormalizeSpecVersion(normalizedSpec); err == nil {
		normalizedSpec = spec
	} else {
		normalizedSpec = "unknown"
	}

	metadata, toolCandidates := parseSpdxMetadata(root["creationInfo"])

	var packagesRaw []json.RawMessage
	_ = json.Unmarshal(root["packages"], &packagesRaw)

	relationships := make(map[string][]Relationship)
	var rels []struct {
		SpdxElementID      string `json:"spdxElementId"`
		RelatedSpdxElement string `json:"relatedSpdxElement"`
		RelationshipType   string `json:"relationshipType"`
	}
	if err := json.Unmarshal(root["relationships"], &rels); err == nil {
		for _, rel := range rels {
			if rel.SpdxElementID == "" || rel.RelatedSpdxElement == "" {
				continue
			}
			relationships[rel.SpdxElementID] = append(relationships[rel.SpdxElementID], Relationship{
				Type:   rel.RelationshipType,
				Target: rel.RelatedSpdxElement,
			})
		}
	}

	components := make([]Component, 0, len(packagesRaw))
	for _, raw := range packagesRaw {
		component, err := parseSpdxPackage(raw, relationships)
		if err != nil {
			return nil, err
		}
		if component.PURL != "" {
			component.PURL = NormalizePURL(component.PURL)
		}
		components = append(components, component)
	}

	producer := detectProducer(toolCandidates)

	return &Document{
		Type: Type{
			Standard:    StandardSPDX,
			SpecVersion: normalizedSpec,
		},
		Producer:   producer,
		Metadata:   metadata,
		Components: components,
	}, nil
}

func parseSpdxMetadata(raw json.RawMessage) (DocumentMetadata, []string) {
	meta := DocumentMetadata{}
	candidates := make([]string, 0)
	if len(raw) == 0 {
		return meta, candidates
	}
	var creation struct {
		Creators []string `json:"creators"`
		Created  string   `json:"created"`
	}
	if err := json.Unmarshal(raw, &creation); err != nil {
		return meta, candidates
	}
	meta.Timestamp = creation.Created
	for _, creator := range creation.Creators {
		trimmed := strings.TrimSpace(creator)
		if trimmed == "" {
			continue
		}
		meta.Authors = append(meta.Authors, stripSpdxPrefix(trimmed))
		candidates = append(candidates, trimmed)
		if tool := extractToolName(trimmed); tool != "" {
			meta.ToolNames = append(meta.ToolNames, tool)
		}
	}
	return meta, candidates
}

func parseSpdxPackage(raw json.RawMessage, relationships map[string][]Relationship) (Component, error) {
	component := Component{Original: raw}
	var data map[string]json.RawMessage
	if err := json.Unmarshal(raw, &data); err != nil {
		return component, err
	}
	spdxID := rawString(data["SPDXID"])
	component.Name = rawString(data["name"])
	component.Version = rawString(data["versionInfo"])
	component.SbomType = strings.ToLower(rawString(data["primaryPackagePurpose"]))

	externalRefs := parseSpdxExternalRefs(data["externalRefs"])
	component.PURL = extractPURL(externalRefs)

	if component.Version == "" {
		component.Version = parsePURLVersion(component.PURL)
	}
	if component.Version == "" {
		component.Version = "unknown"
	}
	identifier := component.Name
	if identifier == "" {
		_, _, name := parsePURL(component.PURL)
		identifier = name
	}
	if identifier == "" && spdxID != "" {
		identifier = spdxID
	}
	if identifier == "" {
		identifier = "unknown"
	}
	if component.PURL == "" {
		component.PURL = buildGenericPURL(identifier, component.Version)
	}
	if component.Name == "" {
		component.Name = identifier
	}
	if component.Type == "" {
		pkgType, _, _ := parsePURL(component.PURL)
		component.Type = pkgType
	}
	if component.Type == "" {
		component.Type = component.SbomType
	}
	if component.Namespace == "" {
		_, namespace, _ := parsePURL(component.PURL)
		component.Namespace = namespace
	}
	if component.Type == "" {
		component.Type = "unknown"
	}
	if component.SbomType == "" {
		component.SbomType = "unknown"
	}

	licenses := parseSpdxLicenses(rawString(data["licenseConcluded"]), rawString(data["licenseDeclared"]))
	component.Licenses = licenses

	supplier := parseSpdxSupplier(rawString(data["supplier"]))
	hashes := parseSpdxChecksums(data["checksums"])

	component.Properties = ComponentProperties{
		Supplier:      supplier,
		Hashes:        hashes,
		Relationships: relationships[spdxID],
		ExternalRefs:  externalRefs,
		SpdxID:        spdxID,
	}

	return component, nil
}

func parseSWID(root map[string]json.RawMessage) (*Document, error) {
	var name string
	_ = json.Unmarshal(root["name"], &name)
	var version string
	_ = json.Unmarshal(root["version"], &version)
	var tagID string
	_ = json.Unmarshal(root["tagId"], &tagID)

	specVersion := "unknown"
	if raw := root["tagVersion"]; len(raw) > 0 {
		var rawValue any
		if err := json.Unmarshal(raw, &rawValue); err == nil {
			switch val := rawValue.(type) {
			case string:
				specVersion = val
			case float64:
				specVersion = strings.TrimRight(strings.TrimRight(fmt.Sprintf("%.2f", val), "0"), ".")
			}
		}
	}
	normalizedSpec, err := NormalizeSpecVersion(specVersion)
	if err != nil {
		normalizedSpec = "unknown"
	}

	identifier := strings.TrimSpace(name)
	if identifier == "" {
		identifier = strings.TrimSpace(tagID)
	}
	if identifier == "" {
		identifier = "unknown"
	}
	if strings.TrimSpace(version) == "" {
		version = "unknown"
	}
	purl := buildGenericPURL(identifier, version)

	component := Component{
		Name:     identifier,
		Version:  version,
		PURL:     purl,
		Type:     "application",
		SbomType: "application",
		Properties: ComponentProperties{
			BomRef: tagID,
		},
	}

	if raw, err := json.Marshal(root); err == nil {
		component.Original = raw
	}

	return &Document{
		Type: Type{
			Standard:    StandardSWID,
			SpecVersion: normalizedSpec,
		},
		Producer:   ProducerOther,
		Components: []Component{component},
	}, nil
}

func parseSpdxSpecVersion(value string) string {
	clean := strings.TrimSpace(value)
	clean = strings.TrimPrefix(clean, "SPDX-")
	clean = strings.TrimPrefix(clean, "SPDX")
	clean = strings.TrimPrefix(clean, "-")
	return clean
}

func stripSpdxPrefix(value string) string {
	trimmed := strings.TrimSpace(value)
	for _, prefix := range []string{"Tool:", "Organization:", "Person:"} {
		if strings.HasPrefix(trimmed, prefix) {
			return strings.TrimSpace(strings.TrimPrefix(trimmed, prefix))
		}
	}
	return trimmed
}

func extractToolName(value string) string {
	trimmed := strings.TrimSpace(value)
	if !strings.HasPrefix(trimmed, "Tool:") {
		return ""
	}
	trimmed = strings.TrimSpace(strings.TrimPrefix(trimmed, "Tool:"))
	if trimmed == "" {
		return ""
	}
	if idx := strings.IndexAny(trimmed, " "); idx > 0 {
		trimmed = trimmed[:idx]
	}
	if idx := strings.Index(trimmed, "-"); idx > 0 {
		return trimmed[:idx]
	}
	return trimmed
}

func parseSpdxSupplier(value string) string {
	clean := strings.TrimSpace(value)
	if clean == "" || strings.EqualFold(clean, "NOASSERTION") || strings.EqualFold(clean, "NONE") {
		return ""
	}
	for _, prefix := range []string{"Organization:", "Person:", "Tool:"} {
		if strings.HasPrefix(clean, prefix) {
			return strings.TrimSpace(strings.TrimPrefix(clean, prefix))
		}
	}
	return clean
}

func parseSpdxLicenses(concluded, declared string) []License {
	licenses := make([]License, 0)
	if concluded != "" && !strings.EqualFold(concluded, "NOASSERTION") {
		licenses = append(licenses, License{Expression: concluded, Source: "licenseConcluded"})
	}
	if declared != "" && !strings.EqualFold(declared, "NOASSERTION") {
		licenses = append(licenses, License{Expression: declared, Source: "licenseDeclared"})
	}
	return licenses
}

func parseCycloneDXLicenses(raw json.RawMessage) []License {
	if len(raw) == 0 {
		return nil
	}
	var entries []map[string]json.RawMessage
	if err := json.Unmarshal(raw, &entries); err != nil {
		return nil
	}
	licenses := make([]License, 0, len(entries))
	for _, entry := range entries {
		if licenseRaw, ok := entry["license"]; ok {
			var lic struct {
				ID   string `json:"id"`
				Name string `json:"name"`
				URL  string `json:"url"`
			}
			if err := json.Unmarshal(licenseRaw, &lic); err == nil {
				licenses = append(licenses, License{ID: lic.ID, Name: lic.Name, URL: lic.URL})
				continue
			}
		}
		if exprRaw, ok := entry["expression"]; ok {
			expr := rawString(exprRaw)
			if expr != "" {
				licenses = append(licenses, License{Expression: expr})
			}
		}
	}
	return licenses
}

func parseProperties(raw json.RawMessage) []Property {
	if len(raw) == 0 {
		return nil
	}
	var props []Property
	if err := json.Unmarshal(raw, &props); err != nil {
		return nil
	}
	return props
}

func derivePackageType(props []Property) string {
	for _, prop := range props {
		name := strings.ToLower(prop.Name)
		switch {
		case name == "syft:package:type":
			return strings.ToLower(prop.Value)
		case strings.HasSuffix(name, ":pkgtype"), strings.Contains(name, "pkgtype"):
			return strings.ToLower(prop.Value)
		}
	}
	return ""
}

func parseSupplierField(raw json.RawMessage) string {
	if len(raw) == 0 {
		return ""
	}
	var supplier struct {
		Name string `json:"name"`
	}
	if err := json.Unmarshal(raw, &supplier); err == nil && supplier.Name != "" {
		return supplier.Name
	}
	var text string
	if err := json.Unmarshal(raw, &text); err == nil {
		return text
	}
	return ""
}

func parseHashes(raw json.RawMessage) []Hash {
	if len(raw) == 0 {
		return nil
	}
	var hashes []Hash
	if err := json.Unmarshal(raw, &hashes); err != nil {
		return nil
	}
	return hashes
}

func parseSpdxChecksums(raw json.RawMessage) []Hash {
	if len(raw) == 0 {
		return nil
	}
	var entries []struct {
		Algorithm string `json:"algorithm"`
		Value     string `json:"checksumValue"`
	}
	if err := json.Unmarshal(raw, &entries); err != nil {
		return nil
	}
	result := make([]Hash, 0, len(entries))
	for _, entry := range entries {
		result = append(result, Hash{Alg: entry.Algorithm, Content: entry.Value})
	}
	return result
}

func parseSpdxExternalRefs(raw json.RawMessage) []ExternalRef {
	if len(raw) == 0 {
		return nil
	}
	var entries []struct {
		Category string `json:"referenceCategory"`
		Type     string `json:"referenceType"`
		Locator  string `json:"referenceLocator"`
	}
	if err := json.Unmarshal(raw, &entries); err != nil {
		return nil
	}
	refs := make([]ExternalRef, 0, len(entries))
	for _, entry := range entries {
		refs = append(refs, ExternalRef{Category: entry.Category, Type: entry.Type, Locator: entry.Locator})
	}
	return refs
}

func extractPURL(refs []ExternalRef) string {
	for _, ref := range refs {
		if strings.EqualFold(ref.Type, "purl") {
			return ref.Locator
		}
	}
	return ""
}

func buildDependencyRelationships(bomRef, purl string, deps map[string][]string) []Relationship {
	key := bomRef
	if key == "" {
		key = purl
	}
	if key == "" {
		return nil
	}
	dependsOn := deps[key]
	if len(dependsOn) == 0 {
		return nil
	}
	relations := make([]Relationship, 0, len(dependsOn))
	for _, dep := range dependsOn {
		if dep == "" {
			continue
		}
		relations = append(relations, Relationship{Type: "DEPENDS_ON", Target: dep})
	}
	return relations
}

func detectProducer(values []string) Producer {
	for _, value := range values {
		candidate := strings.ToLower(value)
		switch {
		case strings.Contains(candidate, string(ProducerTrivy)):
			return ProducerTrivy
		case strings.Contains(candidate, string(ProducerSyft)):
			return ProducerSyft
		case strings.Contains(candidate, string(ProducerGrype)):
			return ProducerGrype
		}
	}
	return ProducerOther
}

func rawString(raw json.RawMessage) string {
	if len(raw) == 0 {
		return ""
	}
	var value string
	if err := json.Unmarshal(raw, &value); err != nil {
		return ""
	}
	return strings.TrimSpace(value)
}

func parsePURL(purl string) (string, string, string) {
	clean := strings.TrimSpace(purl)
	if !strings.HasPrefix(clean, "pkg:") {
		return "", "", ""
	}
	clean = strings.TrimPrefix(clean, "pkg:")
	clean = strings.SplitN(clean, "?", 2)[0]
	clean = strings.SplitN(clean, "#", 2)[0]
	parts := strings.SplitN(clean, "/", 2)
	if len(parts) < 2 {
		return "", "", ""
	}
	pkgType := parts[0]
	rest := strings.SplitN(parts[1], "@", 2)[0]
	segments := strings.Split(rest, "/")
	if len(segments) == 1 {
		return pkgType, "", segments[0]
	}
	return pkgType, strings.Join(segments[:len(segments)-1], "/"), segments[len(segments)-1]
}

func parsePURLVersion(purl string) string {
	clean := strings.TrimSpace(purl)
	if !strings.HasPrefix(clean, "pkg:") {
		return ""
	}
	clean = strings.SplitN(clean, "?", 2)[0]
	clean = strings.SplitN(clean, "#", 2)[0]
	parts := strings.SplitN(clean, "@", 2)
	if len(parts) < 2 {
		return ""
	}
	return parts[1]
}

func buildGenericPURL(name, version string) string {
	if name == "" {
		return ""
	}
	name = strings.TrimSpace(name)
	name = url.PathEscape(name)
	version = strings.TrimSpace(version)
	if version != "" {
		version = url.PathEscape(version)
		return fmt.Sprintf("pkg:generic/%s@%s", name, version)
	}
	return fmt.Sprintf("pkg:generic/%s", name)
}

func NormalizePURL(purl string) string {
	clean := strings.TrimSpace(purl)
	if !strings.HasPrefix(clean, "pkg:") {
		return clean
	}
	fragment := ""
	if idx := strings.Index(clean, "#"); idx >= 0 {
		fragment = clean[idx:]
		clean = clean[:idx]
	}

	parts := strings.SplitN(clean, "?", 2)
	base := parts[0]
	qualifierRaw := ""
	if len(parts) > 1 {
		qualifierRaw = parts[1]
	}

	if qualifierRaw == "" {
		return base + fragment
	}

	qualifiers := strings.Split(qualifierRaw, "&")
	for i, qualifier := range qualifiers {
		pair := strings.SplitN(qualifier, "=", 2)
		if len(pair) != 2 {
			continue
		}
		if pair[0] == "distro" {
			pair[1] = normalizeDistroVersion(pair[1])
			qualifiers[i] = pair[0] + "=" + pair[1]
		}
	}
	return base + "?" + strings.Join(qualifiers, "&") + fragment
}

func normalizeDistroVersion(value string) string {
	clean := strings.TrimSpace(value)
	if clean == "" {
		return clean
	}
	// Example: debian-12.12 -> debian-12
	parts := strings.Split(clean, "-")
	if len(parts) < 2 {
		return clean
	}
	versionPart := parts[len(parts)-1]
	if !strings.Contains(versionPart, ".") {
		return clean
	}
	major := strings.Split(versionPart, ".")[0]
	parts[len(parts)-1] = major
	return strings.Join(parts, "-")
}

// ioReadAll is a wrapper to allow testing in callers.
var ioReadAll = func(r io.Reader) ([]byte, error) {
	return io.ReadAll(r)
}
