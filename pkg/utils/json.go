package utils

// ToJSON converts a value to a JSON string
func ToJSON(v interface{}) (string, error) {
	if v == nil {
		return "", nil
	}
	
	return MarshalJSON(v)
}

// FromJSON parses a JSON string into a value
func FromJSON(jsonStr string, v interface{}) error {
	if jsonStr == "" {
		return nil
	}
	
	return UnmarshalJSON(jsonStr, v)
}
