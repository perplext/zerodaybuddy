package utils

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type testStruct struct {
	Name  string `json:"name"`
	Age   int    `json:"age"`
	Email string `json:"email"`
}

func TestToJSON(t *testing.T) {
	tests := []struct {
		name     string
		input    interface{}
		expected string
		wantErr  bool
	}{
		{
			name:     "simple struct",
			input:    testStruct{Name: "John", Age: 30, Email: "john@example.com"},
			expected: `{"name":"John","age":30,"email":"john@example.com"}`,
			wantErr:  false,
		},
		{
			name:     "empty struct",
			input:    testStruct{},
			expected: `{"name":"","age":0,"email":""}`,
			wantErr:  false,
		},
		{
			name:     "slice",
			input:    []string{"a", "b", "c"},
			expected: `["a","b","c"]`,
			wantErr:  false,
		},
		{
			name:     "map",
			input:    map[string]int{"one": 1, "two": 2},
			expected: `{"one":1,"two":2}`,
			wantErr:  false,
		},
		{
			name:     "nil",
			input:    nil,
			expected: "",
			wantErr:  false,
		},
		{
			name:     "unmarshalable type",
			input:    make(chan int),
			expected: "",
			wantErr:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := ToJSON(tt.input)
			
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				require.NoError(t, err)
				if tt.expected == "" {
					assert.Equal(t, tt.expected, result)
				} else {
					assert.JSONEq(t, tt.expected, result)
				}
			}
		})
	}
}

func TestFromJSON(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		target   interface{}
		expected interface{}
		wantErr  bool
	}{
		{
			name:     "simple struct",
			input:    `{"name":"Jane","age":25,"email":"jane@example.com"}`,
			target:   &testStruct{},
			expected: &testStruct{Name: "Jane", Age: 25, Email: "jane@example.com"},
			wantErr:  false,
		},
		{
			name:     "slice",
			input:    `["x","y","z"]`,
			target:   &[]string{},
			expected: &[]string{"x", "y", "z"},
			wantErr:  false,
		},
		{
			name:     "map",
			input:    `{"three":3,"four":4}`,
			target:   &map[string]int{},
			expected: &map[string]int{"three": 3, "four": 4},
			wantErr:  false,
		},
		{
			name:     "invalid json",
			input:    `{invalid json}`,
			target:   &testStruct{},
			expected: nil,
			wantErr:  true,
		},
		{
			name:     "empty string",
			input:    "",
			target:   &testStruct{},
			expected: &testStruct{},
			wantErr:  false,
		},
		{
			name:     "type mismatch",
			input:    `{"name":"John","age":"not a number"}`,
			target:   &testStruct{},
			expected: nil,
			wantErr:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := FromJSON(tt.input, tt.target)
			
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				require.NoError(t, err)
				assert.Equal(t, tt.expected, tt.target)
			}
		})
	}
}