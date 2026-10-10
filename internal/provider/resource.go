package provider

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"strings"

	"github.com/hashicorp/terraform-plugin-framework-jsontypes/jsontypes"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/tyk-swe/olp/sdk/management"
)

type resourceSpec struct {
	name, create, read, update, destroy, parameter     string
	secret                                             bool
	secretField, rotate, parent, bodyField, collection string
	retiredField                                       string
}
type managedResource struct {
	spec   resourceSpec
	client *managementConnection
}
type resourceModel struct {
	ID         types.String         `tfsdk:"id"`
	Definition jsontypes.Normalized `tfsdk:"definition"`
	ETag       types.String         `tfsdk:"etag"`
	ParentID   types.String
	Scope      types.String
}

func resourceFactories() []func() resource.Resource {
	definitions := []resourceSpec{
		{name: "project", create: "create_project", read: "get_project", update: "update_project", destroy: "delete_project", parameter: "project_id"},
		{name: "budget_group", create: "create_budget_group", read: "get_budget_group", update: "update_budget_group", destroy: "delete_budget_group", parameter: "budget_group_id"},
		{name: "notification_rule", create: "create_notification_rule", read: "get_notification_rule", update: "update_notification_rule", destroy: "delete_notification_rule", parameter: "notification_rule_id"},
		{name: "notification_destination", create: "create_notification_destination", read: "get_notification_destination", update: "update_notification_destination", destroy: "delete_notification_destination", parameter: "notification_destination_id", secret: true},
		{name: "provider", create: "create_provider", read: "get_provider", update: "update_provider", destroy: "delete_provider", parameter: "provider_id", secret: true, secretField: "credential", rotate: "rotate_provider_credential"},
		{name: "credential_slot", create: "put_credential_slot", read: "get_credential_slot", update: "put_credential_slot", destroy: "delete_credential_slot", parameter: "slot_id", secret: true, secretField: "credential", parent: "provider_id", bodyField: "slot", collection: "credential_slots"},
		{name: "mcp_server", create: "create_mcp_server", read: "get_mcp_server", update: "update_mcp_server", destroy: "delete_mcp_server", parameter: "server_id", secret: true, secretField: "credential", retiredField: "retired_at"},
		{name: "sink", create: "create_sink", read: "get_sink", update: "update_sink", destroy: "delete_sink", parameter: "sink_id", secret: true, secretField: "credential", retiredField: "retired_at"},
		{name: "guardrail", create: "create_guardrail", read: "get_guardrail", update: "update_guardrail", destroy: "delete_guardrail", parameter: "guardrail_id", retiredField: "retired_at"},
		{name: "route", create: "create_route", read: "get_route", update: "update_route", destroy: "retire_route", parameter: "route_id", retiredField: "retired_at"},
		{name: "routing_policy", create: "put_routing_policy", read: "get_routing_policy", update: "put_routing_policy", destroy: "delete_routing_policy", parameter: "id", parent: "scope_id", collection: "get_routing_policy"},
		{name: "key", create: "create_api_key", read: "get_api_key", update: "update_api_key", destroy: "revoke_api_key", parameter: "api_key_id", retiredField: "revoked_at"},
	}
	var factories []func() resource.Resource
	for _, spec := range definitions {
		factories = append(factories, func() resource.Resource { return &managedResource{spec: spec} })
	}
	return factories
}

func (r *managedResource) Metadata(_ context.Context, request resource.MetadataRequest, response *resource.MetadataResponse) {
	response.TypeName = request.ProviderTypeName + "_" + r.spec.name
}
func (r *managedResource) Schema(_ context.Context, _ resource.SchemaRequest, response *resource.SchemaResponse) {
	response.Schema = schema.Schema{Description: "An individual " + r.spec.name + " managed with its observed API ETag. Definition is the JSON management request for this resource, excluding secrets and server-owned fields.", Attributes: map[string]schema.Attribute{
		"id":         schema.StringAttribute{Computed: true, PlanModifiers: []planmodifier.String{stringplanmodifier.UseStateForUnknown()}},
		"etag":       schema.StringAttribute{Computed: true},
		"definition": schema.StringAttribute{Required: true, CustomType: jsontypes.NormalizedType{}},
	}}
	if r.spec.secret {
		response.Schema.Attributes["secret"] = schema.StringAttribute{Optional: true, WriteOnly: true, Sensitive: true, Description: "Write-only secret, never retained in plans or state. Increment secret_version when changing it. Use an ephemeral input."}
		response.Schema.Attributes["secret_version"] = schema.Int64Attribute{Optional: true, Description: "Positive change counter for the write-only secret."}
	}
	if r.spec.parent != "" {
		response.Schema.Attributes[r.spec.parent] = schema.StringAttribute{Required: true, PlanModifiers: []planmodifier.String{stringplanmodifier.RequiresReplace()}, Description: "Owning provider UUID. Changing it replaces the credential slot."}
	}
	if r.spec.name == "routing_policy" {
		response.Schema.Attributes["scope"] = schema.StringAttribute{Required: true, PlanModifiers: []planmodifier.String{stringplanmodifier.RequiresReplace()}, Description: "installation, api-key, or route-draft. Installation scope uses the nil UUID."}
		response.Schema.Attributes["scope_id"] = schema.StringAttribute{Required: true, PlanModifiers: []planmodifier.String{stringplanmodifier.RequiresReplace()}, Description: "Scoped resource UUID. Changing it replaces this policy."}
	}
	if r.spec.name == "key" {
		response.Schema.Attributes["secret_file"] = schema.StringAttribute{Optional: true, Description: "Absolute private destination for the one-time generated API key. Only this path enters state. Changes require replacement.", PlanModifiers: []planmodifier.String{stringplanmodifier.RequiresReplace()}}
	}
}

type attributeReader interface {
	GetAttribute(context.Context, path.Path, any) diag.Diagnostics
}
type attributeWriter interface {
	SetAttribute(context.Context, path.Path, any) diag.Diagnostics
}

func readModel(ctx context.Context, source attributeReader, target *resourceModel) diag.Diagnostics {
	var diagnostics diag.Diagnostics
	diagnostics.Append(source.GetAttribute(ctx, path.Root("id"), &target.ID)...)
	diagnostics.Append(source.GetAttribute(ctx, path.Root("etag"), &target.ETag)...)
	diagnostics.Append(source.GetAttribute(ctx, path.Root("definition"), &target.Definition)...)
	return diagnostics
}
func writeModel(ctx context.Context, target attributeWriter, model resourceModel) diag.Diagnostics {
	var diagnostics diag.Diagnostics
	diagnostics.Append(target.SetAttribute(ctx, path.Root("id"), model.ID)...)
	diagnostics.Append(target.SetAttribute(ctx, path.Root("etag"), model.ETag)...)
	diagnostics.Append(target.SetAttribute(ctx, path.Root("definition"), model.Definition)...)
	return diagnostics
}

func (r *managedResource) ValidateConfig(ctx context.Context, request resource.ValidateConfigRequest, response *resource.ValidateConfigResponse) {
	var definition jsontypes.Normalized
	response.Diagnostics.Append(request.Config.GetAttribute(ctx, path.Root("definition"), &definition)...)
	if !definition.IsNull() && !definition.IsUnknown() {
		if _, err := requestDefinition(resourceModel{Definition: definition}); err != nil {
			response.Diagnostics.AddAttributeError(path.Root("definition"), "Invalid definition", err.Error())
		}
	}
	if r.spec.name == "key" {
		var destination types.String
		response.Diagnostics.Append(request.Config.GetAttribute(ctx, path.Root("secret_file"), &destination)...)
		if !destination.IsNull() && !destination.IsUnknown() && !filepath.IsAbs(destination.ValueString()) {
			response.Diagnostics.AddAttributeError(path.Root("secret_file"), "Invalid secret destination", "Use an absolute private file path.")
		}
	}
	if r.spec.name == "routing_policy" {
		var scope, id types.String
		response.Diagnostics.Append(request.Config.GetAttribute(ctx, path.Root("scope"), &scope)...)
		response.Diagnostics.Append(request.Config.GetAttribute(ctx, path.Root("scope_id"), &id)...)
		if !scope.IsUnknown() && !id.IsUnknown() {
			if err := validPolicyIdentity(scope.ValueString(), id.ValueString()); err != nil {
				response.Diagnostics.AddError("Invalid policy identity", err.Error())
			}
		}
	}
	if !r.spec.secret {
		return
	}
	var secret types.String
	var version types.Int64
	response.Diagnostics.Append(request.Config.GetAttribute(ctx, path.Root("secret"), &secret)...)
	response.Diagnostics.Append(request.Config.GetAttribute(ctx, path.Root("secret_version"), &version)...)
	if !version.IsNull() && !version.IsUnknown() && version.ValueInt64() < 1 {
		response.Diagnostics.AddAttributeError(path.Root("secret_version"), "Invalid secret version", "Use a positive change counter.")
	}
	if !secret.IsNull() && !secret.IsUnknown() && version.IsNull() {
		response.Diagnostics.AddAttributeError(path.Root("secret_version"), "Missing secret version", "Supply a positive secret_version with a write-only secret.")
	}
}

func (r *managedResource) withSecret(ctx context.Context, config attributeReader, body json.RawMessage) (json.RawMessage, error) {
	if !r.spec.secret {
		return body, nil
	}
	var secret types.String
	if diagnostics := config.GetAttribute(ctx, path.Root("secret"), &secret); diagnostics.HasError() || secret.IsUnknown() {
		return nil, errors.New("write-only secret must be known when applying")
	}
	if secret.IsNull() {
		return body, nil
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(body, &fields); err != nil {
		return nil, errors.New("invalid resource definition")
	}
	field := r.spec.secretField
	if field == "" {
		field = "secret"
	}
	fields[field], _ = json.Marshal(secret.ValueString())
	return json.Marshal(fields)
}
func (r *managedResource) Configure(_ context.Context, request resource.ConfigureRequest, response *resource.ConfigureResponse) {
	if request.ProviderData == nil {
		return
	}
	var ok bool
	r.client, ok = request.ProviderData.(*managementConnection)
	if !ok {
		response.Diagnostics.AddError("Invalid management client", "Provider configuration did not supply a management client.")
	}
}

func (r *managedResource) call(ctx context.Context, name string, model resourceModel, body json.RawMessage) (management.Response, error) {
	operation, ok := management.Lookup(name)
	if !ok {
		return management.Response{}, fmt.Errorf("management operation %s is unavailable in the generated contract", name)
	}
	args := management.Arguments{Body: body, IfMatch: model.ETag.ValueString()}
	if len(operation.Parameters) > 0 {
		args.Path = map[string]string{}
		for _, parameter := range operation.Parameters {
			if parameter.In != "path" {
				continue
			}
			if r.spec.name == "routing_policy" && parameter.Name == "scope" {
				args.Path[parameter.Name] = model.Scope.ValueString()
			}
			if parameter.Name == r.spec.parameter {
				args.Path[parameter.Name] = model.ID.ValueString()
			}
			if parameter.Name == r.spec.parent {
				args.Path[parameter.Name] = model.ParentID.ValueString()
			}
		}
	}
	if name == r.spec.update || name == r.spec.destroy {
		args.IfMatch = r.observedETag(model)
	}
	result, err := r.client.Call(ctx, operation, args)
	if err == nil && (r.spec.name == "key" || r.spec.name == "provider") && name == r.spec.update {
		r.client.observeParent(model.ID.ValueString(), args.IfMatch, result.ETag)
	}
	if err == nil && r.spec.parent != "" {
		r.client.observeParent(model.ParentID.ValueString(), result.PreviousParentETag, result.ParentETag)
	}
	return result, err
}
func requestDefinition(model resourceModel) (json.RawMessage, error) {
	var object map[string]json.RawMessage
	if model.Definition.IsNull() || model.Definition.IsUnknown() || json.Unmarshal([]byte(model.Definition.ValueString()), &object) != nil || object == nil {
		return nil, errors.New("definition must be a known JSON object")
	}
	for _, field := range []string{"id", "etag", "secret", "credential", "password", "token"} {
		if _, present := object[field]; present {
			return nil, fmt.Errorf("definition cannot contain %s", field)
		}
	}
	return json.RawMessage(model.Definition.ValueString()), nil
}
func decodeResource(result management.Response) (map[string]json.RawMessage, string, error) {
	var object map[string]json.RawMessage
	if json.Unmarshal(result.Body, &object) != nil || object == nil {
		return nil, "", errors.New("management response has no resource object")
	}
	var id string
	if json.Unmarshal(object["id"], &id) != nil || id == "" {
		return nil, "", errors.New("management response has no resource ID")
	}
	return object, id, nil
}

func (r *managedResource) Create(ctx context.Context, request resource.CreateRequest, response *resource.CreateResponse) {
	var model resourceModel
	response.Diagnostics.Append(r.readModel(ctx, request.Plan, &model)...)
	if response.Diagnostics.HasError() {
		return
	}
	body, err := requestDefinition(model)
	if err != nil {
		response.Diagnostics.AddError("Invalid definition", err.Error())
		return
	}
	body, err = r.prepareBody(ctx, request.Config, body, true)
	if err != nil {
		response.Diagnostics.AddError("Invalid write-only secret", err.Error())
		return
	}
	defer clear(body)
	if r.spec.name == "routing_policy" {
		r.createPolicy(ctx, request, response, model, body)
		return
	}
	if r.spec.parent != "" {
		if !r.createChild(ctx, request, response, model, body) {
			return
		}
		return
	}
	result, err := r.call(ctx, r.spec.create, model, body)
	if err != nil {
		response.Diagnostics.AddError("Resource creation failed", err.Error())
		return
	}
	defer clear(result.Body)
	_, id, err := decodeResource(result)
	if err != nil {
		response.Diagnostics.AddError("Invalid creation response", err.Error())
		return
	}
	response.State.Raw = request.Plan.Raw
	model.ID = types.StringValue(id)
	model.ETag = types.StringValue(result.ETag)
	response.Diagnostics.Append(r.writeModel(ctx, &response.State, model)...)
	if r.spec.name == "key" {
		if err = r.captureKey(ctx, request.Config, result.Body); err != nil {
			response.Diagnostics.AddError("Cannot capture API key", err.Error())
		}
	}
}
func (r *managedResource) Read(ctx context.Context, request resource.ReadRequest, response *resource.ReadResponse) {
	var model resourceModel
	response.Diagnostics.Append(r.readModel(ctx, request.State, &model)...)
	if response.Diagnostics.HasError() {
		return
	}
	result, err := r.call(ctx, r.spec.read, model, nil)
	var problem *management.APIError
	if errors.As(err, &problem) && problem.Status == 404 {
		response.State.RemoveResource(ctx)
		return
	}
	if err != nil {
		response.Diagnostics.AddError("Resource refresh failed", err.Error())
		return
	}
	if r.spec.name == "routing_policy" {
		var envelope struct {
			Configured bool            `json:"configured"`
			Policy     json.RawMessage `json:"policy"`
		}
		if json.Unmarshal(result.Body, &envelope) != nil {
			response.Diagnostics.AddError("Invalid policy response", "Management API returned an invalid policy envelope.")
			return
		}
		if !envelope.Configured {
			response.State.RemoveResource(ctx)
			return
		}
		var object map[string]json.RawMessage
		if json.Unmarshal(envelope.Policy, &object) != nil || object == nil {
			response.Diagnostics.AddError("Invalid policy response", "Management API returned no policy object.")
			return
		}
		object["id"], _ = json.Marshal(model.ID.ValueString())
		result.Body, _ = json.Marshal(object)
	}
	object, _, err := decodeResource(result)
	if err != nil {
		response.Diagnostics.AddError("Invalid read response", err.Error())
		return
	}
	if r.spec.retiredField != "" {
		if value, present := object[r.spec.retiredField]; present && string(value) != "null" {
			response.State.RemoveResource(ctx)
			return
		}
	}
	if r.spec.name == "route" {
		if err = flattenRoute(object); err != nil {
			response.Diagnostics.AddError("Invalid route revision response", err.Error())
			return
		}
	}
	if r.spec.name == "key" {
		if err = flattenKeyBudgets(object); err != nil {
			response.Diagnostics.AddError("Invalid key budget response", err.Error())
			return
		}
	}
	if r.spec.name == "provider" || r.spec.parent != "" {
		if err = r.credentialReference(ctx, model, object); err != nil {
			response.Diagnostics.AddError("Cannot read credential reference", err.Error())
			return
		}
	}
	var selected map[string]json.RawMessage
	if !model.Definition.IsNull() && !model.Definition.IsUnknown() {
		if json.Unmarshal([]byte(model.Definition.ValueString()), &selected) != nil {
			response.Diagnostics.AddError("Invalid stored definition", "Stored definition is not a JSON object.")
			return
		}
	} else {
		operation, _ := management.Lookup(r.spec.create)
		selected, err = r.importDefinition(operation, object)
		if err != nil {
			response.Diagnostics.AddError("Cannot import resource definition", err.Error())
			return
		}
	}
	for name := range selected {
		value, exists := object[name]
		if r.spec.name == "provider" && (name == "model" || name == "display_name") {
			// Seeding is a creation intent; inventory is managed independently.
			continue
		}
		if !exists {
			response.Diagnostics.AddError("Incomplete read response", "Management response omitted a configured field.")
			return
		}
		if r.spec.parent != "" && name == "credential_version_id" && string(selected[name]) == "null" {
			continue
		}
		next, projectionErr := projectConfigured(name, selected[name], value)
		if projectionErr != nil {
			response.Diagnostics.AddError("Incomplete read response", projectionErr.Error())
			return
		}
		selected[name] = next
	}
	if r.spec.name == "route" && (model.Definition.IsNull() || model.Definition.IsUnknown()) {
		if err = canonicalRouteTargets(selected); err != nil {
			response.Diagnostics.AddError("Invalid imported targets", err.Error())
			return
		}
	}
	encoded, _ := json.Marshal(selected)
	model.Definition = jsontypes.NewNormalizedValue(string(encoded))
	model.ETag = types.StringValue(result.ETag)
	response.Diagnostics.Append(r.writeModel(ctx, &response.State, model)...)
}
func (r *managedResource) Update(ctx context.Context, request resource.UpdateRequest, response *resource.UpdateResponse) {
	var model, prior resourceModel
	response.Diagnostics.Append(r.readModel(ctx, request.Plan, &model)...)
	response.Diagnostics.Append(r.readModel(ctx, request.State, &prior)...)
	if response.Diagnostics.HasError() {
		return
	}
	model.ID = prior.ID
	model.ETag = prior.ETag
	body, err := requestDefinition(model)
	if err != nil {
		response.Diagnostics.AddError("Invalid definition", err.Error())
		return
	}
	operation, _ := management.Lookup(r.spec.update)
	body, err = r.updateDefinition(operation, body, json.RawMessage(prior.Definition.ValueString()))
	if err != nil {
		response.Diagnostics.AddError("Invalid update definition", err.Error())
		return
	}
	changed := false
	if r.spec.secret {
		var diagnostics diag.Diagnostics
		changed, diagnostics = secretChanged(ctx, request.Plan, request.State)
		response.Diagnostics.Append(diagnostics...)
		if response.Diagnostics.HasError() {
			return
		}
	}
	if r.spec.bodyField != "" {
		var fields, old map[string]json.RawMessage
		json.Unmarshal(body, &fields)
		json.Unmarshal([]byte(prior.Definition.ValueString()), &old)
		if sameJSON(fields["credential_reference"], old["credential_reference"]) {
			delete(fields, "credential_reference")
		}
		body, _ = json.Marshal(fields)
	}
	body, err = r.prepareBody(ctx, request.Config, body, changed && r.spec.rotate == "")
	if err != nil {
		response.Diagnostics.AddError("Invalid write-only secret", err.Error())
		return
	}
	defer clear(body)
	result, err := r.call(ctx, r.spec.update, model, body)
	if err != nil {
		response.Diagnostics.AddError("Resource update failed", err.Error())
		return
	}
	if r.spec.parent != "" {
		// Slot PUT returns the pool; refresh the committed slot's own ETag.
		response.State.Raw = request.Plan.Raw
		response.Diagnostics.Append(r.writeModel(ctx, &response.State, model)...)
		result, err = r.call(ctx, r.spec.read, model, nil)
		if err != nil {
			response.Diagnostics.AddError("Cannot refresh committed slot", err.Error())
			return
		}
	}
	response.State.Raw = request.Plan.Raw
	model.ETag = types.StringValue(result.ETag)
	response.Diagnostics.Append(r.writeModel(ctx, &response.State, model)...)
	if changed && r.spec.rotate != "" {
		// Validate a replacement against the newly committed draft configuration.
		// If validation fails, retain that configuration and the prior counter.
		response.Diagnostics.Append(setSecretVersion(ctx, request.State, &response.State)...)
		if !response.Diagnostics.HasError() {
			r.rotateSecret(ctx, request, response, &model)
		}
	}
}
func (r *managedResource) Delete(ctx context.Context, request resource.DeleteRequest, response *resource.DeleteResponse) {
	var model resourceModel
	response.Diagnostics.Append(r.readModel(ctx, request.State, &model)...)
	if response.Diagnostics.HasError() {
		return
	}
	_, err := r.call(ctx, r.spec.destroy, model, nil)
	var problem *management.APIError
	if err != nil && !(errors.As(err, &problem) && problem.Status == 404) {
		response.Diagnostics.AddError("Resource destruction failed", err.Error())
	}
}
func (r *managedResource) ImportState(ctx context.Context, request resource.ImportStateRequest, response *resource.ImportStateResponse) {
	if r.spec.parent != "" {
		r.importChild(ctx, request, response)
		return
	}
	resource.ImportStatePassthroughID(ctx, path.Root("id"), request, response)
}

func (r *managedResource) ModifyPlan(ctx context.Context, request resource.ModifyPlanRequest, response *resource.ModifyPlanResponse) {
	if r.client == nil {
		return
	}
	if request.State.Raw.IsNull() {
		if request.Plan.Raw.IsNull() {
			return
		}
		// New-resource plans check the live collection's read authority without
		// acquiring installation-wide configuration-promotion permissions.
		name := r.spec.collection
		if name == "" {
			name = "list_" + strings.TrimPrefix(r.spec.create, "create_") + "s"
		}
		operation, exists := management.Lookup(name)
		if !exists {
			response.Diagnostics.AddError("Cannot validate resource collection", "Generated contract has no collection read for this resource.")
			return
		}
		var planned resourceModel
		response.Diagnostics.Append(r.readModel(ctx, request.Plan, &planned)...)
		if response.Diagnostics.HasError() {
			return
		}
		if r.spec.parent != "" && planned.ParentID.IsUnknown() {
			return
		}
		if r.spec.name == "routing_policy" {
			planned.ID = planned.ParentID
		}
		if _, err := r.call(ctx, operation.Name, planned, nil); err != nil {
			response.Diagnostics.AddError("Cannot plan resource creation", err.Error())
		}
		return
	}
	var model resourceModel
	response.Diagnostics.Append(r.readModel(ctx, request.State, &model)...)
	if response.Diagnostics.HasError() {
		return
	}
	if !request.Plan.Raw.IsNull() {
		var planned resourceModel
		response.Diagnostics.Append(r.readModel(ctx, request.Plan, &planned)...)
		if response.Diagnostics.HasError() {
			return
		}
		operation, _ := management.Lookup(r.spec.update)
		body, err := r.bodySchema(operation)
		if err != nil {
			response.Diagnostics.AddError("Invalid update contract", err.Error())
			return
		}
		var previous, next map[string]json.RawMessage
		if json.Unmarshal([]byte(model.Definition.ValueString()), &previous) == nil && !planned.Definition.IsUnknown() && json.Unmarshal([]byte(planned.Definition.ValueString()), &next) == nil {
			if r.spec.name == "route" {
				if err := validateRouteReplacement(previous, next); err != nil {
					response.Diagnostics.AddError("Invalid route replacement", err.Error())
					return
				}
			}
			for field := range previous {
				if _, present := next[field]; !present {
					if _, mutable := body.Properties[field]; !mutable || (r.spec.name == "route" && field == "slug") {
						response.RequiresReplace = append(response.RequiresReplace, path.Root("definition"))
						break
					}
				}
			}
			for field, value := range next {
				if _, mutable := body.Properties[field]; (!mutable || (r.spec.name == "route" && field == "slug")) && !equivalentValue(field, previous[field], value) {
					response.RequiresReplace = append(response.RequiresReplace, path.Root("definition"))
					break
				}
			}
		}
	}
	current, err := r.call(ctx, r.spec.read, model, nil)
	if err != nil {
		response.Diagnostics.AddError("Cannot verify planned resource", err.Error())
		return
	}
	if current.ETag != r.observedETag(model) {
		response.Diagnostics.AddError("Resource changed while planning", "Refresh and review a new plan before applying. The observed resource ETag is stale.")
	}
}
