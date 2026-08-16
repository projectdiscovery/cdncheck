package generate

import (
	"reflect"
	"testing"
)

func TestAppendUniqueCIDRs(t *testing.T) {
	tests := []struct {
		name     string
		existing []string
		incoming []string
		want     []string
	}{
		{
			name:     "merge disjoint",
			existing: []string{"10.0.0.0/24"},
			incoming: []string{"10.0.1.0/24", "2001:db8::/32"},
			want:     []string{"10.0.0.0/24", "10.0.1.0/24", "2001:db8::/32"},
		},
		{
			name:     "dedupe overlap",
			existing: []string{"10.0.0.0/24", "10.0.1.0/24"},
			incoming: []string{"10.0.1.0/24", "10.0.2.0/24"},
			want:     []string{"10.0.0.0/24", "10.0.1.0/24", "10.0.2.0/24"},
		},
		{
			name:     "nil existing",
			existing: nil,
			incoming: []string{"10.0.0.0/24", "10.0.0.0/24"},
			want:     []string{"10.0.0.0/24"},
		},
		{
			name:     "empty incoming preserves existing identity",
			existing: []string{"10.0.0.0/24"},
			incoming: nil,
			want:     []string{"10.0.0.0/24"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := appendUniqueCIDRs(tt.existing, tt.incoming)
			if !reflect.DeepEqual(got, tt.want) {
				t.Fatalf("got %v, want %v", got, tt.want)
			}
		})
	}
}
