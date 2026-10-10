package provider

import (
	"encoding/json"
	"testing"
)

func TestRouteTargetsRetainSelectedFactsAndImportOneCanonicalSelector(t *testing.T) {
	previous := json.RawMessage(`[{"provider_id":"provider","provider_model":"model","weight":1,"timeout_ms":2000}]`)
	actual := json.RawMessage(`[{"id":"internal","provider_model_id":"canonical","provider_id":"provider","provider_model":"model","provider_name":"private","weight":2,"timeout_ms":2000,"priority":0}]`)
	selected, err := projectConfigured("targets", previous, actual)
	if err != nil || string(selected) != `[{"provider_id":"provider","provider_model":"model","timeout_ms":2000,"weight":2}]` {
		t.Fatalf("configured target facts: %s %v", selected, err)
	}
	definition := map[string]json.RawMessage{"targets": actual}
	if err := canonicalRouteTargets(definition); err != nil {
		t.Fatal(err)
	}
	var targets []map[string]json.RawMessage
	if err := json.Unmarshal(definition["targets"], &targets); err != nil {
		t.Fatal(err)
	}
	if string(targets[0]["provider_model_id"]) != `"canonical"` || targets[0]["provider_id"] != nil || targets[0]["provider_name"] != nil || targets[0]["id"] != nil {
		t.Fatal("import retained conflicting selectors or server metadata")
	}
}

func TestRouteProjectReplacementRequiresANewSlug(t *testing.T) {
	previous := map[string]json.RawMessage{"slug": json.RawMessage(`"retained"`)}
	unchanged := map[string]json.RawMessage{"slug": json.RawMessage(`"retained"`), "project_id": json.RawMessage(`null`)}
	if err := validateRouteReplacement(previous, unchanged); err != nil {
		t.Fatal("omitted and null project are equivalent", err)
	}
	unchanged["project_id"] = json.RawMessage(`"new-project"`)
	if err := validateRouteReplacement(previous, unchanged); err == nil {
		t.Fatal("replacement would retire the old route then fail on its reserved slug")
	}
	unchanged["slug"] = json.RawMessage(`"new-slug"`)
	if err := validateRouteReplacement(previous, unchanged); err != nil {
		t.Fatal(err)
	}
}
