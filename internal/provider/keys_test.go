package provider

import (
	"encoding/json"
	"testing"
)

func TestKeyBudgetProjectionRetainsExactLimitsAndIgnoresAccountingFields(t *testing.T) {
	object := map[string]json.RawMessage{"budget": json.RawMessage(`{"daily":{"limit":"10.000000000001","spent":"7","remaining":"3"},"monthly":{"limit":null},"enforcement_active":true,"unpriced_attempts":2}`)}
	if err := flattenKeyBudgets(object); err != nil {
		t.Fatal(err)
	}
	if string(object["daily_cost_limit"]) != `"10.000000000001"` || string(object["monthly_cost_limit"]) != "null" || string(object["weekly_cost_limit"]) != "null" {
		t.Fatalf("incorrect editable ceilings: %s", object["daily_cost_limit"])
	}
}
