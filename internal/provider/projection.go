package provider

import (
	"encoding/json"
	"errors"
)

// Keep only fields chosen by the operator, recursively. The API's normalized
// defaults must not create an endless diff, while changes to chosen facts are
// still reflected in refreshed state.
func projectConfigured(name string, configured, observed json.RawMessage) (json.RawMessage, error) {
	var desired map[string]json.RawMessage
	if json.Unmarshal(configured, &desired) == nil && desired != nil {
		var actual map[string]json.RawMessage
		if json.Unmarshal(observed, &actual) != nil || actual == nil {
			return observed, nil
		}
		for field, previous := range desired {
			value, present := actual[field]
			if !present {
				return nil, errors.New("management response omitted a configured nested field")
			}
			next, err := projectConfigured(field, previous, value)
			if err != nil {
				return nil, err
			}
			desired[field] = next
		}
		return json.Marshal(desired)
	}
	if equivalentValue(name, configured, observed) {
		return configured, nil
	}
	return observed, nil
}
