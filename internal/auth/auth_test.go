package auth

import (
	"errors"
	"net/http"
	"testing"
)

func TestGetAPIKey(t *testing.T) {
	tests := []struct {
		name    string
		headers http.Header
		want    string
		wantErr error
	}{
		{
			name:    "No authorization header",
			headers: http.Header{},
			want:    "",
			wantErr: ErrNoAuthHeaderIncluded,
		},
		{
			name: "Malformed authorization header (missing value)",
			headers: http.Header{
				"Authorization": []string{"ApiKey"},
			},
			want:    "",
			wantErr: errors.New("malformed authorization header"),
		},
		{
			name: "Malformed authorization header (wrong scheme)",
			headers: http.Header{
				"Authorization": []string{"Bearer somekey"},
			},
			want:    "",
			wantErr: errors.New("malformed authorization header"),
		},
		{
			name: "Valid authorization header",
			headers: http.Header{
				"Authorization": []string{"ApiKey somekey"},
			},
			want:    "somekey",
			wantErr: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := GetAPIKey(tt.headers)
			if got != tt.want {
				t.Errorf("GetAPIKey() = %v, want %v", got, tt.want)
			}
			if err != nil && err.Error() != tt.wantErr.Error() {
				t.Errorf("GetAPIKey() error = %v, wantErr %v", err, tt.wantErr)
			}
			if err == nil && tt.wantErr != nil {
				t.Errorf("GetAPIKey() error = nil, wantErr %v", tt.wantErr)
			}
		})
	}
}
