package provider

import (
	"encoding/json"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework-jsontypes/jsontypes"
	"github.com/tyk-swe/olp/sdk/management"
)

func TestImportUsesGeneratedMutableFieldsAndNeverResponseSecrets(t *testing.T) {
	operation, _ := management.Lookup("create_project")
	fields := map[string]json.RawMessage{"name": json.RawMessage(`"Production"`), "id": json.RawMessage(`"server-id"`), "etag": json.RawMessage(`"observed"`), "secret": json.RawMessage(`"private-value"`)}
	definition, err := importDefinition(operation, fields)
	if err != nil || len(definition) != 1 || string(definition["name"]) != `"Production"` {
		t.Fatalf("imported definition %v, error %v", definition, err)
	}
}

func TestDefinitionsCannotSmuggleCredentialValuesIntoState(t *testing.T) {
	for _, definition := range []string{`null`, `[]`, `{"credential":"private"}`, `{"secret":"private"}`, `{"id":"server-owned"}`, `{"password":"private"}`} {
		if _, err := requestDefinition(resourceModel{Definition: jsontypes.NewNormalizedValue(definition)}); err == nil {
			t.Fatalf("accepted state-bearing definition %s", definition)
		}
	}
}

func TestUpdatesExcludeImmutableCreationFieldsAndPreserveDecimalSemantics(t *testing.T) {
	operation, _ := management.Lookup("update_budget_group")
	body, err := updateDefinition(operation, json.RawMessage(`{"name":"Budget","project_id":"immutable-project","monthly_cost_limit":"10"}`), nil)
	var object map[string]any
	if err != nil || json.Unmarshal(body, &object) != nil || len(object) != 2 || object["project_id"] != nil {
		t.Fatalf("update fields %s: %v", body, err)
	}
	if !equivalentValue("monthly_cost_limit", json.RawMessage(`"10"`), json.RawMessage(`"10.000000000000"`)) {
		t.Fatal("fixed storage scale changed the desired monetary value")
	}
	if equivalentValue("name", json.RawMessage(`"010"`), json.RawMessage(`"10"`)) || equivalentValue("monthly_cost_limit", json.RawMessage(`"10"`), json.RawMessage(`"11"`)) {
		t.Fatal("real remote changes were hidden")
	}
}

func TestRemovedNullableBudgetCeilingIsExplicitlyCleared(t *testing.T) {
	operation, _ := management.Lookup("update_budget_group")
	body, err := updateDefinition(operation, json.RawMessage(`{"name":"Budget","daily_cost_limit":"10"}`), json.RawMessage(`{"name":"Budget","monthly_cost_limit":"20"}`))
	var fields map[string]json.RawMessage
	if err != nil || json.Unmarshal(body, &fields) != nil || string(fields["monthly_cost_limit"]) != "null" {
		t.Fatalf("removed ceiling remains hidden: %s, %v", body, err)
	}
}
