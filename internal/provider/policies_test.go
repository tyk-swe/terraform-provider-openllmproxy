package provider

import (
	"encoding/json"
	"testing"

	"github.com/google/uuid"
	"github.com/tyk-swe/olp/sdk/management"
)

func TestPolicyIdentityRequiresCanonicalScopeAndBoundary(t *testing.T) {
	id := uuid.NewString()
	for _, value := range []struct{ scope, id string }{{"installation", uuid.Nil.String()}, {"api-key", id}, {"route-draft", id}} {
		if err := validPolicyIdentity(value.scope, value.id); err != nil {
			t.Fatal(err)
		}
	}
	for _, value := range []struct{ scope, id string }{{"installation", id}, {"api-key", uuid.Nil.String()}, {"unknown", id}, {"route-draft", "not-a-uuid"}} {
		if validPolicyIdentity(value.scope, value.id) == nil {
			t.Fatalf("accepted invalid policy boundary %v", value)
		}
	}
}

func TestPolicyReplacementClearsOmittedConstraints(t *testing.T) {
	r := managedResource{spec: resourceSpec{name: "routing_policy"}}
	desired := json.RawMessage(`{"allowed_strategies":["weighted"]}`)
	body, err := r.updateDefinition(management.Operation{}, desired, json.RawMessage(`{"constraints":{"regions":["west"]}}`))
	if err != nil || string(body) != string(desired) {
		t.Fatalf("replacement retained an omitted constraint: %s %v", body, err)
	}
}
