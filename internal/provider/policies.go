package provider

import (
	"context"
	"encoding/json"
	"errors"

	"github.com/google/uuid"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/tyk-swe/olp/sdk/management"
)

func validPolicyIdentity(scope, id string) error {
	parsed, err := uuid.Parse(id)
	if err != nil || parsed.String() != id {
		return errors.New("use a canonical scoped resource UUID")
	}
	switch scope {
	case "installation":
		if parsed != uuid.Nil {
			return errors.New("installation scope uses the nil UUID")
		}
	case "api-key", "route-draft":
		if parsed == uuid.Nil {
			return errors.New("resource scope requires its resource UUID")
		}
	default:
		return errors.New("use installation, api-key, or route-draft scope")
	}
	return nil
}

func (r *managedResource) createPolicy(ctx context.Context, request resource.CreateRequest, response *resource.CreateResponse, model resourceModel, body json.RawMessage) {
	model.ID = model.ParentID
	result, err := r.call(ctx, r.spec.read, model, nil)
	if err != nil {
		response.Diagnostics.AddError("Cannot observe policy before creation", err.Error())
		return
	}
	var current struct {
		Configured bool `json:"configured"`
	}
	if json.Unmarshal(result.Body, &current) != nil {
		response.Diagnostics.AddError("Invalid policy response", "Management API returned an invalid policy envelope.")
		return
	}
	if current.Configured {
		response.Diagnostics.AddError("Routing policy already exists", "Import the existing explicit policy before managing it.")
		return
	}
	model.ETag = types.StringValue(result.ETag)
	result, err = r.call(ctx, r.spec.create, model, body)
	if err != nil {
		var apiError *management.APIError
		if !errors.As(err, &apiError) || apiError.Status >= 500 {
			response.State.Raw = request.Plan.Raw
			response.Diagnostics.Append(r.writeModel(ctx, &response.State, model)...)
		}
		response.Diagnostics.AddError("Policy creation failed", err.Error())
		return
	}
	model.ETag = types.StringValue(result.ETag)
	response.State.Raw = request.Plan.Raw
	response.Diagnostics.Append(r.writeModel(ctx, &response.State, model)...)
}
