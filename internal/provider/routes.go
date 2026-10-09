package provider

import (
	"encoding/json"
	"errors"
)

func validateRouteReplacement(previous, next map[string]json.RawMessage) error {
	project := func(value json.RawMessage) json.RawMessage {
		if len(value) == 0 {
			return json.RawMessage("null")
		}
		return value
	}
	if !sameJSON(project(previous["project_id"]), project(next["project_id"])) && sameJSON(previous["slug"], next["slug"]) {
		return errors.New("a published route's project cannot change under its retained slug; choose a new slug for the replacement")
	}
	return nil
}

func flattenRoute(object map[string]json.RawMessage) error {
	var revision map[string]json.RawMessage
	if err := json.Unmarshal(object["latest_revision"], &revision); err != nil {
		return err
	}
	for name, value := range revision {
		if _, present := object[name]; !present {
			object[name] = value
		}
	}
	return nil
}

// Imported targets use their canonical model identity. Supplying both that and
// provider/model selectors would be an invalid write request.
func canonicalRouteTargets(definition map[string]json.RawMessage) error {
	var targets []map[string]json.RawMessage
	if err := json.Unmarshal(definition["targets"], &targets); err != nil {
		return err
	}
	for _, target := range targets {
		for name := range target {
			switch name {
			case "provider_model_id", "priority", "weight", "timeout_ms", "tags", "shadow":
			default:
				delete(target, name)
			}
		}
	}
	encoded, err := json.Marshal(targets)
	if err == nil {
		definition["targets"] = encoded
	}
	return err
}
