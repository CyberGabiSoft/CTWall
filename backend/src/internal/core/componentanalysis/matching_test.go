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

func TestMatchSmart_AllVersionsWhenMalwareVersionUnknown(t *testing.T) {
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

	matched, matchType, malwarePURL := matchSmart(component, candidate)
	if !matched {
		t.Fatalf("expected match")
	}
	if matchType != store.ComponentAnalysisMatchContainsPrefix {
		t.Fatalf("expected CONTAINS_PREFIX, got %q", matchType)
	}
	if malwarePURL != "pkg:deb/debian/apt" {
		t.Fatalf("unexpected malware purl %q", malwarePURL)
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

func TestMatchSmart_FallbackPrefixWhenComponentVersionMissing(t *testing.T) {
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

	matched, matchType, malwarePURL := matchSmart(component, candidate)
	if !matched {
		t.Fatalf("expected match")
	}
	if matchType != store.ComponentAnalysisMatchContainsPrefix {
		t.Fatalf("expected CONTAINS_PREFIX, got %q", matchType)
	}
	if malwarePURL != "pkg:golang/example.com/go-app" {
		t.Fatalf("unexpected malware purl %q", malwarePURL)
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
