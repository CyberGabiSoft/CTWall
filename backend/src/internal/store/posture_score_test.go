package store

import "testing"

func TestApplySecurityPostureScore_BasedOnMalwareProductsRatio(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name            string
		totalProducts   int
		malwareProducts int
		want            int
	}{
		{
			name:            "no products defaults to 100",
			totalProducts:   0,
			malwareProducts: 0,
			want:            100,
		},
		{
			name:            "all clean products",
			totalProducts:   10,
			malwareProducts: 0,
			want:            100,
		},
		{
			name:            "half malware products",
			totalProducts:   10,
			malwareProducts: 5,
			want:            50,
		},
		{
			name:            "all malware products",
			totalProducts:   7,
			malwareProducts: 7,
			want:            0,
		},
		{
			name:            "clamped malware ratio above one",
			totalProducts:   3,
			malwareProducts: 9,
			want:            0,
		},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			overview := &SecurityPostureOverview{
				KPIs: SecurityPostureKPIs{
					TotalProducts:   tc.totalProducts,
					MalwareProducts: tc.malwareProducts,
				},
			}
			ApplySecurityPostureScore(overview)

			if overview.Score.Value != tc.want {
				t.Fatalf("expected score=%d, got %d", tc.want, overview.Score.Value)
			}
			if overview.Score.Label != "" {
				t.Fatalf("expected empty score label, got %q", overview.Score.Label)
			}
		})
	}
}
