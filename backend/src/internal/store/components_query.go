package store

// ComponentListFilter defines server-side filters for listing Components.
// All fields are expected to be already sanitized/validated by the API layer.
type ComponentListFilter struct {
	Query        string
	PkgName      string
	PURL         string
	PkgType      string
	PkgNamespace string
	Version      string
	SbomType     string
	Publisher    string
	Supplier     string
}

type ComponentListSort struct {
	Field string
	Desc  bool
}

