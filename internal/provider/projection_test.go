package provider

import (
	"encoding/json"
	"testing"

	"github.com/tyk-swe/olp/sdk/management"
)

func TestNormalizedDefaultsDoNotHideChangesToConfiguredNestedFacts(t *testing.T) {
	desired := json.RawMessage(`{"kind":"openai_compatible","options":{"models":{},"vendor_id":"openai"}}`)
	actual := json.RawMessage(`{"kind":"openai_compatible","cloud_region":null,"options":{"models":{},"vendor_id":"different","credential_headers":[],"parameter_defaults":{}}}`)
	projected, err := projectConfigured("configuration", desired, actual)
	if err != nil || !sameJSON(projected, json.RawMessage(`{"kind":"openai_compatible","options":{"models":{},"vendor_id":"different"}}`)) {
		t.Fatalf("projection %s: %v", projected, err)
	}
	if _, err = projectConfigured("configuration", desired, json.RawMessage(`{"options":{}}`)); err == nil {
		t.Fatal("missing selected facts were silently discarded")
	}
}

func TestSlotDefinitionsUseTheGeneratedNestedContractWithoutImportingIdentity(t *testing.T) {
	r := managedResource{spec: resourceSpec{bodyField: "slot"}}
	operation, _ := management.Lookup("put_credential_slot")
	schema, err := r.bodySchema(operation)
	if err != nil || len(schema.Properties) < 10 {
		t.Fatalf("slot schema: %v", err)
	}
	object := map[string]json.RawMessage{"id": json.RawMessage(`"server-owned"`), "etag": json.RawMessage(`"observed"`), "name": json.RawMessage(`"Pool member"`), "credential": json.RawMessage(`"private"`)}
	imported, err := r.importDefinition(operation, object)
	if err != nil || len(imported) != 1 || string(imported["name"]) != `"Pool member"` {
		t.Fatalf("import %v: %v", imported, err)
	}
	object["credential_reference"] = json.RawMessage(`{"store":"vault","secret_id":"https://vault.example/v1/secret/data/provider","version":"7","field":"api_key"}`)
	object["credential_version_id"] = json.RawMessage(`"immutable-version-id"`)
	imported, err = r.importDefinition(operation, object)
	if err != nil || imported["credential_reference"] == nil || imported["credential_version_id"] != nil {
		t.Fatalf("reference import selected conflicting sources: %v: %v", imported, err)
	}
}
