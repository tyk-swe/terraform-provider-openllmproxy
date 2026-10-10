package provider

import (
	"context"
	"sync"

	"github.com/tyk-swe/olp/sdk/management"
)

// New slots share a collection precondition until they have individual ETags.
// Serialize this client's initial pool reads/writes; external conflicts still
// fail through the API's ordinary conditional mutation path.
type managementConnection struct {
	*management.Client
	mu      sync.Mutex
	pools   map[string]chan struct{}
	parents map[string]map[string]string
}

func (r *managedResource) observedETag(model resourceModel) string {
	observed := model.ETag.ValueString()
	if r.spec.name == "key" || r.spec.name == "provider" {
		return r.client.advanceParent(model.ID.ValueString(), observed)
	}
	if r.spec.name == "routing_policy" && model.Scope.ValueString() != "installation" {
		return r.client.advanceParent(model.ParentID.ValueString(), observed)
	}
	return observed
}

func (c *managementConnection) observeParent(id, previous, current string) {
	if previous == "" || current == "" || previous == current {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.parents == nil {
		c.parents = make(map[string]map[string]string)
	}
	if c.parents[id] == nil {
		c.parents[id] = make(map[string]string)
	}
	// A conflicting transition cannot justify advancing an observation.
	if value, exists := c.parents[id][previous]; exists && value != current {
		current = ""
	}
	c.parents[id][previous] = current
}

func (c *managementConnection) advanceParent(id, observed string) string {
	c.mu.Lock()
	defer c.mu.Unlock()
	transitions := c.parents[id]
	for range len(transitions) {
		next := transitions[observed]
		if next == "" {
			break
		}
		observed = next
	}
	return observed
}

func (c *managementConnection) lockPool(ctx context.Context, id string) (func(), error) {
	c.mu.Lock()
	if c.pools == nil {
		c.pools = make(map[string]chan struct{})
	}
	lock := c.pools[id]
	if lock == nil {
		lock = make(chan struct{}, 1)
		c.pools[id] = lock
	}
	c.mu.Unlock()
	select {
	case lock <- struct{}{}:
		return func() { <-lock }, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}
