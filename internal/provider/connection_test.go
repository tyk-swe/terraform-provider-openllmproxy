package provider

import "testing"

func TestParentTransitionsAccountForOwnChildWritesWithoutBorrowingExternalEdits(t *testing.T) {
	c := new(managementConnection)
	// Concurrent responses can arrive out of transaction order.
	c.observeParent("one", "second", "third")
	c.observeParent("one", "first", "second")
	c.observeParent("two", "third", "foreign")
	if got := c.advanceParent("one", "first"); got != "third" {
		t.Fatalf("own chain: %s", got)
	}
	// An intervening external edit creates a gap; its ETag cannot be adopted.
	c.observeParent("one", "external", "fourth")
	if got := c.advanceParent("one", "third"); got != "third" {
		t.Fatalf("external edit adopted: %s", got)
	}
	c.observeParent("one", "first", "conflicting")
	if got := c.advanceParent("one", "first"); got != "first" {
		t.Fatalf("conflicting chain adopted: %s", got)
	}
}
