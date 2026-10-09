// Package provider manages individual OLP resources through the generated
// management client. Bearer values are always read from a mounted file.
package provider

import (
	"context"
	"os"

	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/provider"
	"github.com/hashicorp/terraform-plugin-framework/provider/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/tyk-swe/olp/sdk/management"
)

type managementProvider struct{ version string }
type connectionModel struct {
	URL       types.String `tfsdk:"url"`
	TokenFile types.String `tfsdk:"token_file"`
}

func New(version string) func() provider.Provider {
	return func() provider.Provider { return &managementProvider{version: version} }
}
func (p *managementProvider) Metadata(_ context.Context, _ provider.MetadataRequest, response *provider.MetadataResponse) {
	response.TypeName = "openllmproxy"
	response.Version = p.version
}
func (p *managementProvider) Schema(_ context.Context, _ provider.SchemaRequest, response *provider.SchemaResponse) {
	response.Schema = schema.Schema{Description: "Manage individual OpenLLMProxy installation resources with scoped tokens and observed ETags.", Attributes: map[string]schema.Attribute{
		"url":        schema.StringAttribute{Optional: true, Description: "HTTPS installation origin; defaults to OLP_MANAGEMENT_URL. Loopback HTTP is permitted for development."},
		"token_file": schema.StringAttribute{Optional: true, Description: "Mounted management-token file; defaults to OLP_MANAGEMENT_TOKEN_FILE. Its value is reread for every call and never placed in Terraform state."},
	}}
}
func (p *managementProvider) Configure(ctx context.Context, request provider.ConfigureRequest, response *provider.ConfigureResponse) {
	var model connectionModel
	response.Diagnostics.Append(request.Config.Get(ctx, &model)...)
	if response.Diagnostics.HasError() {
		return
	}
	if model.URL.IsUnknown() || model.TokenFile.IsUnknown() {
		response.Diagnostics.AddError("Unknown installation connection", "Installation URL and token-file path must be known during planning.")
		return
	}
	endpoint, tokenFile := model.URL.ValueString(), model.TokenFile.ValueString()
	if model.URL.IsNull() {
		endpoint = os.Getenv("OLP_MANAGEMENT_URL")
	}
	if model.TokenFile.IsNull() {
		tokenFile = os.Getenv("OLP_MANAGEMENT_TOKEN_FILE")
	}
	client, err := management.NewClient(endpoint, tokenFile)
	if err != nil {
		response.Diagnostics.AddError("Invalid installation connection", err.Error())
		return
	}
	response.ResourceData = &managementConnection{Client: client}
}
func (p *managementProvider) Resources(_ context.Context) []func() resource.Resource {
	return resourceFactories()
}
func (p *managementProvider) DataSources(_ context.Context) []func() datasource.DataSource {
	return nil
}
