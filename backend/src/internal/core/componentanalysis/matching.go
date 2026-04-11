package componentanalysis

import (
	"encoding/json"
	"net/url"
	"strings"

	"backend/internal/sbom"
	"backend/internal/store"
)

// PURLVersionSmartMode documents strict version-aware malware matching:
// exact base PURL + exact version match from OSV affected[].versions.
const PURLVersionSmartMode = "PURL_VERSION_SMART"

type malwareMatchCandidateLister interface {
	ListMalwareMatchCandidates(componentPURL string) ([]store.MalwareMatchCandidate, error)
}

func matchSmart(componentPURL string, candidate store.MalwareMatchCandidate) (bool, string, string) {
	componentBase, componentVersion := normalizePURLBaseAndVersion(componentPURL)
	malwareBase, malwareVersionFromPURL := normalizePURLBaseAndVersion(candidate.ComponentPURL)
	if componentBase == "" || malwareBase == "" {
		return false, "", ""
	}
	if !strings.EqualFold(componentBase, malwareBase) {
		return false, "", ""
	}

	// Smart mode is strictly version-aware: if component version is unknown,
	// this mode does not emit a match (prefix mode handles that path).
	if componentVersion == "" {
		return false, "", ""
	}

	// If OSV affected.package.purl already carries a concrete version, treat it as
	// a strict smart constraint (component.version must be exactly that version).
	if malwareVersionFromPURL != "" && componentVersion != malwareVersionFromPURL {
		return false, "", ""
	}

	malwareVersions := resolveMalwareVersions(candidate, malwareBase)

	// When OSV provides a concrete version in package.purl, that explicit value is
	// sufficient for smart matching (versions[] list is optional in that path).
	// If versions[] exists as well, keep it consistent with the selected version.
	if malwareVersionFromPURL != "" {
		if len(malwareVersions) > 0 && !containsVersion(malwareVersions, componentVersion) {
			return false, "", ""
		}
		return true, store.ComponentAnalysisMatchExact, buildVersionedPURL(malwareBase, componentVersion)
	}

	// Smart mode requires explicit affected versions and exact version equality.
	if len(malwareVersions) == 0 {
		return false, "", ""
	}
	if !containsVersion(malwareVersions, componentVersion) {
		return false, "", ""
	}
	return true, store.ComponentAnalysisMatchExact, buildVersionedPURL(malwareBase, componentVersion)
}

func matchContainsPrefix(componentPURL string, candidate store.MalwareMatchCandidate) (bool, string) {
	componentBase, _ := normalizePURLBaseAndVersion(componentPURL)
	malwareBase, _ := normalizePURLBaseAndVersion(candidate.ComponentPURL)
	if componentBase == "" || malwareBase == "" {
		return false, ""
	}
	if !strings.EqualFold(componentBase, malwareBase) {
		return false, ""
	}
	return true, malwareBase
}

type osvDetailsForMatch struct {
	Affected []osvAffectedForMatch `json:"affected"`
}

type osvAffectedForMatch struct {
	Package struct {
		PURL string `json:"purl"`
	} `json:"package"`
	Versions []string `json:"versions"`
}

func resolveMalwareVersions(candidate store.MalwareMatchCandidate, malwareBase string) []string {
	return extractOSVAffectedVersions(candidate.DetailsJSON, malwareBase)
}

func extractOSVAffectedVersions(details json.RawMessage, malwareBase string) []string {
	if len(details) == 0 || strings.TrimSpace(malwareBase) == "" {
		return nil
	}
	var payload osvDetailsForMatch
	if err := json.Unmarshal(details, &payload); err != nil {
		return nil
	}
	if len(payload.Affected) == 0 {
		return nil
	}

	out := make([]string, 0)
	seen := make(map[string]struct{})
	for _, affected := range payload.Affected {
		affectedBase, _ := normalizePURLBaseAndVersion(affected.Package.PURL)
		if affectedBase == "" || !strings.EqualFold(affectedBase, malwareBase) {
			continue
		}
		for _, rawVersion := range affected.Versions {
			version := normalizePlainVersion(rawVersion)
			if version == "" {
				continue
			}
			if _, ok := seen[version]; ok {
				continue
			}
			seen[version] = struct{}{}
			out = append(out, version)
		}
	}
	return out
}

func containsVersion(versions []string, componentVersion string) bool {
	for _, version := range versions {
		if version == componentVersion {
			return true
		}
	}
	return false
}

func normalizePURLBaseAndVersion(raw string) (string, string) {
	clean := sbom.NormalizePURL(strings.TrimSpace(raw))
	if clean == "" {
		return "", ""
	}
	fragmentFree := strings.SplitN(clean, "#", 2)[0]
	basePart := fragmentFree
	rawQuery := ""
	if idx := strings.Index(fragmentFree, "?"); idx >= 0 {
		basePart = fragmentFree[:idx]
		rawQuery = fragmentFree[idx+1:]
	}
	lastSlash := strings.LastIndex(basePart, "/")
	lastAt := strings.LastIndex(basePart, "@")
	versionDelimiter := "@"
	delimiterIndex := lastAt
	if delimiterIndex <= lastSlash {
		// Compatibility: accept non-standard "name:version" PURLs (seen in some PyPI exports)
		// and treat ":" after the package path as a version separator.
		lastColon := strings.LastIndex(basePart, ":")
		if lastColon > lastSlash {
			versionDelimiter = ":"
			delimiterIndex = lastColon
		}
	}
	if delimiterIndex <= lastSlash {
		return strings.TrimSpace(basePart), ""
	}
	base := strings.TrimSpace(basePart[:delimiterIndex])
	version := normalizeVersionWithEpoch(basePart[delimiterIndex+len(versionDelimiter):], rawQuery)
	if strings.EqualFold(version, "unknown") {
		version = ""
	}
	return base, version
}

func normalizeVersionWithEpoch(versionRaw, rawQuery string) string {
	version := normalizePlainVersion(versionRaw)
	if version == "" {
		return ""
	}
	values, err := url.ParseQuery(rawQuery)
	if err != nil {
		return version
	}
	epoch := strings.TrimSpace(values.Get("epoch"))
	if epoch != "" && !strings.Contains(version, ":") {
		version = epoch + ":" + version
	}
	return version
}

func normalizePlainVersion(raw string) string {
	clean := strings.TrimSpace(raw)
	if clean == "" {
		return ""
	}
	decoded, err := url.PathUnescape(clean)
	if err == nil {
		clean = decoded
	}
	clean = strings.TrimSpace(clean)
	if strings.EqualFold(clean, "unknown") {
		return ""
	}
	return clean
}

func buildVersionedPURL(base, version string) string {
	base = strings.TrimSpace(base)
	version = normalizePlainVersion(version)
	if base == "" || version == "" {
		return base
	}
	return base + "@" + url.PathEscape(version)
}

func matchPriority(matchType string) int {
	switch strings.ToUpper(strings.TrimSpace(matchType)) {
	case store.ComponentAnalysisMatchExact:
		return 2
	case store.ComponentAnalysisMatchContainsPrefix:
		return 1
	default:
		return 0
	}
}
