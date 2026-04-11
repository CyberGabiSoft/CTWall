package componentanalysis

import (
	"testing"

	"backend/internal/store"
)

func TestMatchSmart_ExactByOSVVersionsList(t *testing.T) {
	component := "pkg:deb/debian/apt@2.6.1"
	candidate := store.MalwareMatchCandidate{
		ComponentPURL: "pkg:deb/debian/apt",
		DetailsJSON: []byte(`{
			"id":"MAL-APT",
			"affected":[
				{"package":{"purl":"pkg:deb/debian/apt"},"versions":["2.5.0","2.6.1","2.7.0"]}
			]
		}`),
	}

	matched, matchType, malwarePURL := matchSmart(component, candidate)
	if !matched {
		t.Fatalf("expected match")
	}
	if matchType != store.ComponentAnalysisMatchExact {
		t.Fatalf("expected EXACT, got %q", matchType)
	}
	if malwarePURL != "pkg:deb/debian/apt@2.6.1" {
		t.Fatalf("unexpected malware purl %q", malwarePURL)
	}
}

func TestMatchSmart_NoMatchWhenVersionMissingInOSVVersionsList(t *testing.T) {
	component := "pkg:deb/debian/apt@2.8.0"
	candidate := store.MalwareMatchCandidate{
		ComponentPURL: "pkg:deb/debian/apt",
		DetailsJSON: []byte(`{
			"id":"MAL-APT",
			"affected":[
				{"package":{"purl":"pkg:deb/debian/apt"},"versions":["2.5.0","2.6.1","2.7.0"]}
			]
		}`),
	}

	matched, _, _ := matchSmart(component, candidate)
	if matched {
		t.Fatalf("expected no match")
	}
}

func TestMatchSmart_NoMatchWhenMalwareVersionUnknown(t *testing.T) {
	component := "pkg:deb/debian/apt@2.6.1"
	candidate := store.MalwareMatchCandidate{
		ComponentPURL: "pkg:deb/debian/apt",
		DetailsJSON: []byte(`{
			"id":"MAL-APT",
			"affected":[
				{"package":{"purl":"pkg:deb/debian/apt"}}
			]
		}`),
	}

	matched, _, _ := matchSmart(component, candidate)
	if matched {
		t.Fatalf("expected no match")
	}
}

func TestMatchSmart_NoMatchForDifferentVersion(t *testing.T) {
	component := "pkg:deb/debian/apt@2.6.1"
	candidate := store.MalwareMatchCandidate{
		ComponentPURL: "pkg:deb/debian/apt",
		DetailsJSON: []byte(`{
			"id":"MAL-APT",
			"affected":[
				{"package":{"purl":"pkg:deb/debian/apt"},"versions":["2.7.0"]}
			]
		}`),
	}

	matched, _, _ := matchSmart(component, candidate)
	if matched {
		t.Fatalf("expected no match")
	}
}

func TestMatchSmart_NoMatchWhenComponentVersionMissing(t *testing.T) {
	component := "pkg:golang/example.com/go-app"
	candidate := store.MalwareMatchCandidate{
		ComponentPURL: "pkg:golang/example.com/go-app",
		DetailsJSON: []byte(`{
			"id":"MAL-GOAPP",
			"affected":[
				{"package":{"purl":"pkg:golang/example.com/go-app"},"versions":["1.2.3","1.2.4"]}
			]
		}`),
	}

	matched, _, _ := matchSmart(component, candidate)
	if matched {
		t.Fatalf("expected no match")
	}
}

func TestMatchSmart_EpochNormalization(t *testing.T) {
	component := "pkg:deb/debian/bsdutils@2.38.1-5%2Bdeb12u3?arch=amd64&distro=debian-12&epoch=1"
	candidate := store.MalwareMatchCandidate{
		ComponentPURL: "pkg:deb/debian/bsdutils",
		DetailsJSON: []byte(`{
			"id":"MAL-BSDUTILS",
			"affected":[
				{"package":{"purl":"pkg:deb/debian/bsdutils"},"versions":["1:2.38.1-5+deb12u3"]}
			]
		}`),
	}

	matched, matchType, malwarePURL := matchSmart(component, candidate)
	if !matched {
		t.Fatalf("expected match")
	}
	if matchType != store.ComponentAnalysisMatchExact {
		t.Fatalf("expected EXACT, got %q", matchType)
	}
	if malwarePURL != "pkg:deb/debian/bsdutils@1:2.38.1-5+deb12u3" &&
		malwarePURL != "pkg:deb/debian/bsdutils@1%3A2.38.1-5+deb12u3" &&
		malwarePURL != "pkg:deb/debian/bsdutils@1%3A2.38.1-5%2Bdeb12u3" {
		t.Fatalf("unexpected malware purl %q", malwarePURL)
	}
}

func TestMatchSmart_NonStandardColonVersionNormalization(t *testing.T) {
	component := "pkg:pypi/databaseroboats:0.0.3"
	candidate := store.MalwareMatchCandidate{
		ComponentPURL: "pkg:pypi/databaseroboats",
		DetailsJSON: []byte(`{
			"id":"MAL-DATABASEROBOATS",
			"affected":[
				{"package":{"purl":"pkg:pypi/databaseroboats"},"versions":["0.0.3"]}
			]
		}`),
	}

	matched, matchType, malwarePURL := matchSmart(component, candidate)
	if !matched {
		t.Fatalf("expected match")
	}
	if matchType != store.ComponentAnalysisMatchExact {
		t.Fatalf("expected EXACT, got %q", matchType)
	}
	if malwarePURL != "pkg:pypi/databaseroboats@0.0.3" {
		t.Fatalf("unexpected malware purl %q", malwarePURL)
	}
}

func TestMatchSmart_ExplicitCandidateVersionMustMatchComponentVersion(t *testing.T) {
	component := "pkg:pypi/databaseroboats@0.0.4"
	candidate := store.MalwareMatchCandidate{
		ComponentPURL: "pkg:pypi/databaseroboats@0.0.3",
		DetailsJSON: []byte(`{
			"id":"MAL-DATABASEROBOATS",
			"affected":[
				{"package":{"purl":"pkg:pypi/databaseroboats"},"versions":["0.0.3","0.0.4"]}
			]
		}`),
	}

	matched, _, _ := matchSmart(component, candidate)
	if matched {
		t.Fatalf("expected no match when OSV package.purl version differs from component version")
	}
}

func TestMatchSmart_ExplicitCandidateVersionWithoutVersionsListStillMatches(t *testing.T) {
	component := "pkg:pypi/databaseroboats@0.0.3"
	candidate := store.MalwareMatchCandidate{
		ComponentPURL: "pkg:pypi/databaseroboats@0.0.3",
		DetailsJSON: []byte(`{
			"id":"MAL-DATABASEROBOATS",
			"affected":[
				{"package":{"purl":"pkg:pypi/databaseroboats@0.0.3"}}
			]
		}`),
	}

	matched, matchType, malwarePURL := matchSmart(component, candidate)
	if !matched {
		t.Fatalf("expected match")
	}
	if matchType != store.ComponentAnalysisMatchExact {
		t.Fatalf("expected EXACT, got %q", matchType)
	}
	if malwarePURL != "pkg:pypi/databaseroboats@0.0.3" {
		t.Fatalf("unexpected malware purl %q", malwarePURL)
	}
}

func TestMatchSmart_ExplicitCandidateVersionMustBeConsistentWithVersionsList(t *testing.T) {
	component := "pkg:pypi/databaseroboats@0.0.3"
	candidate := store.MalwareMatchCandidate{
		ComponentPURL: "pkg:pypi/databaseroboats@0.0.3",
		DetailsJSON: []byte(`{
			"id":"MAL-DATABASEROBOATS",
			"affected":[
				{"package":{"purl":"pkg:pypi/databaseroboats@0.0.3"},"versions":["0.0.4"]}
			]
		}`),
	}

	matched, _, _ := matchSmart(component, candidate)
	if matched {
		t.Fatalf("expected no match when explicit package.purl version is inconsistent with versions[]")
	}
}
