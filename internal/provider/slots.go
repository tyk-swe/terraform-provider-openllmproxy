package provider

import (
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"strings"

	"github.com/google/uuid"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/tyk-swe/olp/sdk/management"
)

func sameJSON(left, right json.RawMessage) bool {
	if len(left) == 0 || len(right) == 0 {
		return len(left) == len(right)
	}
	var a, b any
	return json.Unmarshal(left, &a) == nil && json.Unmarshal(right, &b) == nil && reflect.DeepEqual(a, b)
}

func (r *managedResource) createChild(ctx context.Context, request resource.CreateRequest, response *resource.CreateResponse, model resourceModel, body json.RawMessage) bool {
	if _, err := uuid.Parse(model.ParentID.ValueString()); err != nil {
		response.Diagnostics.AddError("Invalid provider", "Use the owning provider UUID.")
		return false
	}
	unlock, err := r.client.lockPool(ctx, model.ParentID.ValueString())
	if err != nil {
		response.Diagnostics.AddError("Cannot acquire credential pool", "The request was canceled.")
		return false
	}
	defer unlock()
	pool, err := r.call(ctx, r.spec.collection, model, nil)
	if err != nil {
		response.Diagnostics.AddError("Cannot read credential pool", err.Error())
		return false
	}
	model.ID = types.StringValue(uuid.NewString())
	model.ETag = types.StringValue(pool.ETag)
	result, err := r.call(ctx, r.spec.create, model, body)
	clear(result.Body)
	if err != nil {
		var apiError *management.APIError
		if !errors.As(err, &apiError) || apiError.Status >= 500 {
			// A transport failure can follow a committed PUT. Keep its chosen UUID
			// so refresh can adopt that slot rather than create another credential.
			response.State.Raw = request.Plan.Raw
			response.Diagnostics.Append(r.writeModel(ctx, &response.State, model)...)
		}
		response.Diagnostics.AddError("Create failed", err.Error())
		return false
	}
	response.State.Raw = request.Plan.Raw
	response.Diagnostics.Append(r.writeModel(ctx, &response.State, model)...)
	read, err := r.call(ctx, r.spec.read, model, nil)
	if err != nil {
		response.Diagnostics.AddError("Cannot refresh committed slot", err.Error())
		return false
	}
	model.ETag = types.StringValue(read.ETag)
	response.Diagnostics.Append(r.writeModel(ctx, &response.State, model)...)
	return !response.Diagnostics.HasError()
}

func (r *managedResource) importChild(ctx context.Context, request resource.ImportStateRequest, response *resource.ImportStateResponse) {
	if r.spec.name == "routing_policy" {
		scope, id, found := strings.Cut(request.ID, "/")
		if !found || validPolicyIdentity(scope, id) != nil {
			response.Diagnostics.AddError("Invalid import identity", "Use installation/NIL_UUID, api-key/KEY_UUID, or route-draft/DRAFT_UUID.")
			return
		}
		response.Diagnostics.Append(response.State.SetAttribute(ctx, path.Root("scope"), scope)...)
		response.Diagnostics.Append(response.State.SetAttribute(ctx, path.Root("scope_id"), id)...)
		response.Diagnostics.Append(response.State.SetAttribute(ctx, path.Root("id"), id)...)
		return
	}
	parent, child, found := strings.Cut(request.ID, "/")
	_, parentError := uuid.Parse(parent)
	_, childError := uuid.Parse(child)
	if !found || parentError != nil || childError != nil {
		response.Diagnostics.AddError("Invalid slot import", "Use PROVIDER_UUID/SLOT_UUID.")
		return
	}
	response.Diagnostics.Append(response.State.SetAttribute(ctx, path.Root("id"), child)...)
	response.Diagnostics.Append(response.State.SetAttribute(ctx, path.Root(r.spec.parent), parent)...)
}

// External references are nonsecret metadata, read from the same immutable
// credential version selected by the draft/default slot.
func (r *managedResource) credentialReference(ctx context.Context, model resourceModel, object map[string]json.RawMessage) error {
	var id string
	field := "draft_credential_id"
	providerID := model.ID.ValueString()
	if r.spec.parent != "" {
		field = "credential_version_id"
		providerID = model.ParentID.ValueString()
	}
	json.Unmarshal(object[field], &id)
	if id == "" {
		return nil
	}
	operation, exists := management.Lookup("list_provider_credentials")
	if !exists {
		return errors.New("credential metadata operation missing")
	}
	query := map[string]any{}
	for range 128 {
		result, err := r.client.Call(ctx, operation, management.Arguments{Path: map[string]string{"provider_id": providerID}, Query: query})
		if err != nil {
			return err
		}
		var page struct {
			Items []struct {
				ID        string          `json:"id"`
				Reference json.RawMessage `json:"external_reference"`
			} `json:"items"`
			NextCursor *string `json:"next_cursor"`
		}
		if json.Unmarshal(result.Body, &page) != nil {
			return errors.New("invalid credential metadata response")
		}
		for _, credential := range page.Items {
			if credential.ID == id {
				if len(credential.Reference) > 0 && string(credential.Reference) != "null" {
					object["credential_reference"] = credential.Reference
				}
				return nil
			}
		}
		if page.NextCursor == nil || *page.NextCursor == "" {
			return nil
		}
		query["cursor"] = *page.NextCursor
	}
	return errors.New("credential inventory exceeds the bounded import search")
}
