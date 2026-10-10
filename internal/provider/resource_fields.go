package provider

import (
	"context"
	"encoding/json"
	"errors"
	"strings"

	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/tyk-swe/olp/sdk/management"
)

func (r *managedResource) readModel(ctx context.Context, source attributeReader, target *resourceModel) diag.Diagnostics {
	diagnostics := readModel(ctx, source, target)
	if r.spec.name == "routing_policy" {
		diagnostics.Append(source.GetAttribute(ctx, path.Root("scope"), &target.Scope)...)
	}
	if r.spec.parent != "" {
		diagnostics.Append(source.GetAttribute(ctx, path.Root(r.spec.parent), &target.ParentID)...)
	}
	return diagnostics
}

func (r *managedResource) writeModel(ctx context.Context, target attributeWriter, model resourceModel) diag.Diagnostics {
	diagnostics := writeModel(ctx, target, model)
	if r.spec.name == "routing_policy" {
		diagnostics.Append(target.SetAttribute(ctx, path.Root("scope"), model.Scope)...)
	}
	if r.spec.parent != "" {
		diagnostics.Append(target.SetAttribute(ctx, path.Root(r.spec.parent), model.ParentID)...)
	}
	return diagnostics
}

// Flatten the slot wrapper only for Terraform's definition handling; transport
// continues to use the original contract operation and request shape.
func (r *managedResource) definitionOperation(operation management.Operation) (management.Operation, error) {
	if r.spec.bodyField == "" {
		return operation, nil
	}
	var input inputSchema
	if json.Unmarshal(operation.InputSchema, &input) != nil {
		return operation, errors.New("invalid generated resource schema")
	}
	resolve := func(value inputSchema) (inputSchema, error) {
		if value.Reference == "" {
			return value, nil
		}
		name, valid := strings.CutPrefix(value.Reference, "#/$defs/")
		resolved, exists := input.Definitions[name]
		if !valid || !exists {
			return value, errors.New("missing generated resource schema")
		}
		return resolved, nil
	}
	body, err := resolve(input.Properties["body"])
	if err != nil {
		return operation, err
	}
	fields, err := resolve(body.Properties[r.spec.bodyField])
	if err != nil {
		return operation, err
	}
	fields.Properties["credential_reference"] = body.Properties["credential_reference"]
	input.Properties["body"] = fields
	operation.InputSchema, err = json.Marshal(input)
	return operation, err
}

func (r *managedResource) bodySchema(operation management.Operation) (inputSchema, error) {
	operation, err := r.definitionOperation(operation)
	if err != nil {
		return inputSchema{}, err
	}
	return bodySchema(operation)
}

func (r *managedResource) importDefinition(operation management.Operation, object map[string]json.RawMessage) (map[string]json.RawMessage, error) {
	operation, err := r.definitionOperation(operation)
	if err != nil {
		return nil, err
	}
	definition, err := importDefinition(operation, object)
	if err == nil && r.spec.bodyField != "" && len(definition["credential_reference"]) > 0 {
		// A pinned reference and an existing-version selector are alternative
		// credential sources; an imported definition must remain writable.
		delete(definition, "credential_version_id")
	}
	return definition, err
}

func (r *managedResource) updateDefinition(operation management.Operation, desired, prior json.RawMessage) (json.RawMessage, error) {
	if r.spec.name == "routing_policy" {
		// Policy PUT replaces the entire policy. Omitted optional facts return
		// to defaults; they do not have merge-patch retention semantics.
		return desired, nil
	}
	operation, err := r.definitionOperation(operation)
	if err != nil {
		return nil, err
	}
	return updateDefinition(operation, desired, prior)
}

func (r *managedResource) prepareBody(ctx context.Context, config attributeReader, body json.RawMessage, secret bool) (json.RawMessage, error) {
	if r.spec.bodyField != "" {
		var fields map[string]json.RawMessage
		if json.Unmarshal(body, &fields) != nil {
			return nil, errors.New("invalid resource definition")
		}
		reference, present := fields["credential_reference"]
		delete(fields, "credential_reference")
		encoded, err := json.Marshal(fields)
		if err != nil {
			return nil, err
		}
		wrapper := map[string]json.RawMessage{r.spec.bodyField: encoded}
		if present {
			wrapper["credential_reference"] = reference
		}
		body, err = json.Marshal(wrapper)
		if err != nil {
			return nil, err
		}
	}
	if secret {
		return r.withSecret(ctx, config, body)
	}
	return body, nil
}

func secretChanged(ctx context.Context, desired, prior attributeReader) (bool, diag.Diagnostics) {
	var next, previous types.Int64
	var diagnostics diag.Diagnostics
	diagnostics.Append(desired.GetAttribute(ctx, path.Root("secret_version"), &next)...)
	diagnostics.Append(prior.GetAttribute(ctx, path.Root("secret_version"), &previous)...)
	return !next.Equal(previous), diagnostics
}

func setSecretVersion(ctx context.Context, source attributeReader, state attributeWriter) diag.Diagnostics {
	var version types.Int64
	diagnostics := source.GetAttribute(ctx, path.Root("secret_version"), &version)
	if !diagnostics.HasError() {
		diagnostics.Append(state.SetAttribute(ctx, path.Root("secret_version"), version)...)
	}
	return diagnostics
}

func (r *managedResource) rotateSecret(ctx context.Context, request resource.UpdateRequest, response *resource.UpdateResponse, model *resourceModel) bool {
	body, err := r.withSecret(ctx, request.Config, json.RawMessage(`{}`))
	if err != nil {
		response.Diagnostics.AddError("Invalid write-only secret", err.Error())
		return false
	}
	defer clear(body)
	result, err := r.call(ctx, r.spec.rotate, *model, body)
	if err != nil {
		response.Diagnostics.AddError("Credential validation failed", err.Error())
		return false
	}
	defer clear(result.Body)
	model.ETag = types.StringValue(result.ETag)
	// Record the validated credential only after it commits. A failed validation
	// leaves the already committed draft configuration and prior counter intact.
	response.Diagnostics.Append(response.State.SetAttribute(ctx, path.Root("etag"), model.ETag)...)
	response.Diagnostics.Append(setSecretVersion(ctx, request.Plan, &response.State)...)
	return !response.Diagnostics.HasError()
}
