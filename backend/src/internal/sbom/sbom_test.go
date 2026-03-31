package sbom

import (
	"os"
	"path/filepath"
	"testing"
)

func loadFixture(t *testing.T, relativePath ...string) []byte {
	t.Helper()
	root := repoRoot(t)
	parts := append([]string{root, "sboms"}, relativePath...)
	path := filepath.Join(parts...)
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	return data
}

func repoRoot(t *testing.T) string {
	t.Helper()
	wd, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	current := wd
	for i := 0; i < 10; i++ {
		if info, err := os.Stat(filepath.Join(current, "sboms")); err == nil && info.IsDir() {
			return current
		}
		parent := filepath.Dir(current)
		if parent == current {
			break
		}
		current = parent
	}
	t.Fatalf("sboms directory not found from %s", wd)
	return ""
}

func TestParseCycloneDXFixtures(t *testing.T) {
	cases := []struct {
		name       string
		path       []string
		producer   Producer
		components int
	}{
		{
			name:       "syft-cyclonedx-1.6",
			path:       []string{"sbom_syft_cyclonedx", "out_cyclonedx_syft_1_6.json"},
			producer:   ProducerSyft,
			components: 3107,
		},
		{
			name:       "trivy-cyclonedx-1.6",
			path:       []string{"sbom_trivy_cyclonedx", "trivy_out.json"},
			producer:   ProducerTrivy,
			components: 121,
		},
	}
	for _, tc := range cases {
		data := loadFixture(t, tc.path...)
		doc, err := Parse(data)
		if err != nil {
			t.Fatalf("%s: parse error: %v", tc.name, err)
		}
		if doc.Type.Standard != StandardCycloneDX {
			t.Fatalf("%s: unexpected standard %s", tc.name, doc.Type.Standard)
		}
		if doc.Type.SpecVersion == "" || doc.Type.SpecVersion == "unknown" {
			t.Fatalf("%s: expected specVersion, got %q", tc.name, doc.Type.SpecVersion)
		}
		if tc.producer != "" && doc.Producer != tc.producer {
			t.Fatalf("%s: expected producer %s, got %s", tc.name, tc.producer, doc.Producer)
		}
		if len(doc.Components) != tc.components {
			t.Fatalf("%s: expected %d components, got %d", tc.name, tc.components, len(doc.Components))
		}
		if doc.Components[0].Name == "" || doc.Components[0].PURL == "" {
			t.Fatalf("%s: expected component name and purl", tc.name)
		}
	}
}

func TestParseSpdxFixture(t *testing.T) {
	data := loadFixture(t, "sbom_syft_cyclonedx", "spdx-json-2.3.json")
	doc, err := Parse(data)
	if err != nil {
		t.Fatalf("parse error: %v", err)
	}
	if doc.Type.Standard != StandardSPDX {
		t.Fatalf("expected spdx standard, got %s", doc.Type.Standard)
	}
	if doc.Type.SpecVersion == "" {
		t.Fatalf("expected specVersion")
	}
	if len(doc.Components) == 0 {
		t.Fatalf("expected components parsed")
	}
}

func TestParseSWIDPayloadUnsupported(t *testing.T) {
	payload := []byte(`{"tagId":"swid:generated-ctwall","name":"generated-ctwall","version":"1.2.3","tagVersion":1}`)
	if _, err := Parse(payload); err == nil {
		t.Fatalf("expected unsupported sbom format error for swid payload")
	}
}
