package store

import "testing"

func TestComponentBasePURL(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name string
		in   string
		want string
	}{
		{
			name: "standard at-version",
			in:   "pkg:pypi/databaseroboats@0.0.3",
			want: "pkg:pypi/databaseroboats",
		},
		{
			name: "non-standard colon-version",
			in:   "pkg:pypi/databaseroboats:0.0.3",
			want: "pkg:pypi/databaseroboats",
		},
		{
			name: "no version",
			in:   "pkg:pypi/databaseroboats",
			want: "pkg:pypi/databaseroboats",
		},
		{
			name: "empty",
			in:   "   ",
			want: "",
		},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got := componentBasePURL(tc.in)
			if got != tc.want {
				t.Fatalf("componentBasePURL(%q) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}
