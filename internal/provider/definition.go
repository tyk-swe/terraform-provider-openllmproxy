package provider

import (
	"bytes"
	"encoding/json"
	"errors"
	"math/big"
	"strings"

	"github.com/tyk-swe/olp/sdk/management"
)

type inputSchema struct {
	Reference   string                 `json:"$ref"`
	Properties  map[string]inputSchema `json:"properties"`
	Definitions map[string]inputSchema `json:"$defs"`
	Type        any                    `json:"type"`
	Default     json.RawMessage        `json:"default"`
	WriteOnly   bool                   `json:"writeOnly"`
}

// Import projects only mutable creation fields from the generated contract;
// IDs, audit timestamps and one-time response secrets stay out of definition.
func importDefinition(operation management.Operation, object map[string]json.RawMessage) (map[string]json.RawMessage, error) {
	body, err := bodySchema(operation)
	if err != nil {
		return nil, err
	}
	result := map[string]json.RawMessage{}
	for name, property := range body.Properties {
		if property.WriteOnly || name == "secret" || name == "credential" {
			continue
		}
		if value, exists := object[name]; exists && !bytes.Equal(bytes.TrimSpace(value), []byte("null")) {
			result[name] = value
		}
	}
	if len(result) == 0 {
		return nil, errors.New("resource response contains no mutable definition fields")
	}
	return result, nil
}

func bodySchema(operation management.Operation) (inputSchema, error) {
	var input inputSchema
	if json.Unmarshal(operation.InputSchema, &input) != nil {
		return inputSchema{}, errors.New("invalid generated resource schema")
	}
	body := input.Properties["body"]
	if body.Reference != "" {
		name, valid := strings.CutPrefix(body.Reference, "#/$defs/")
		if !valid {
			return inputSchema{}, errors.New("unsupported generated schema reference")
		}
		var exists bool
		body, exists = input.Definitions[name]
		if !exists {
			return inputSchema{}, errors.New("missing generated resource definition")
		}
	}
	return body, nil
}

// Monetary columns have fixed storage scale. Keep an equivalent configured
// decimal spelling while still detecting a real remote value change.
func equivalentValue(name string, configured, observed json.RawMessage) bool {
	if bytes.Equal(configured, observed) {
		return true
	}
	if !strings.HasSuffix(name, "_cost_limit") {
		return false
	}
	var left, right string
	if json.Unmarshal(configured, &left) != nil || json.Unmarshal(observed, &right) != nil {
		return false
	}
	a, aOK := new(big.Rat).SetString(left)
	b, bOK := new(big.Rat).SetString(right)
	return aOK && bOK && a.Cmp(b) == 0
}

func updateDefinition(operation management.Operation, definition, prior json.RawMessage) (json.RawMessage, error) {
	schema, err := bodySchema(operation)
	if err != nil {
		return nil, err
	}
	var fields map[string]json.RawMessage
	if json.Unmarshal(definition, &fields) != nil {
		return nil, errors.New("definition must be a JSON object")
	}
	for name := range fields {
		if _, allowed := schema.Properties[name]; !allowed {
			delete(fields, name)
		}
	}
	var previous map[string]json.RawMessage
	if len(prior) > 0 && json.Unmarshal(prior, &previous) != nil {
		return nil, errors.New("invalid prior definition")
	}
	for name := range previous {
		if _, present := fields[name]; present {
			continue
		}
		property, mutable := schema.Properties[name]
		if !mutable {
			continue
		}
		if permitsNull(property.Type) {
			fields[name] = json.RawMessage("null")
		} else if len(property.Default) > 0 {
			fields[name] = property.Default
		} else {
			return nil, errors.New("removed field " + name + " requires an explicit desired value")
		}
	}
	return json.Marshal(fields)
}

func permitsNull(value any) bool {
	switch types := value.(type) {
	case string:
		return types == "null"
	case []any:
		for _, kind := range types {
			if kind == "null" {
				return true
			}
		}
	}
	return false
}
