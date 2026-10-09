package provider

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"

	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

func flattenKeyBudgets(object map[string]json.RawMessage) error {
	var windows map[string]json.RawMessage
	if json.Unmarshal(object["budget"], &windows) != nil {
		return errors.New("management key response has no budget windows")
	}
	for _, window := range []string{"daily", "monthly", "weekly"} {
		raw, present := windows[window]
		var value struct {
			Limit json.RawMessage `json:"limit"`
		}
		if present && json.Unmarshal(raw, &value) != nil {
			return errors.New("invalid management budget window")
		}
		if !present || len(value.Limit) == 0 {
			object[window+"_cost_limit"] = json.RawMessage("null")
		} else {
			object[window+"_cost_limit"] = value.Limit
		}
	}
	return nil
}

// The generated secret goes directly to a private file; only its destination
// path is state-bearing. Atomic replacement prevents partial mounted values.
func (r *managedResource) captureKey(ctx context.Context, config attributeReader, body json.RawMessage) error {
	var destination types.String
	if config.GetAttribute(ctx, path.Root("secret_file"), &destination).HasError() || destination.IsUnknown() {
		return errors.New("key secret destination must be known when applying")
	}
	if destination.IsNull() {
		return nil
	}
	name := destination.ValueString()
	if !filepath.IsAbs(name) {
		return errors.New("key secret destination must be an absolute file path")
	}
	var value struct {
		Secret string `json:"secret"`
	}
	if json.Unmarshal(body, &value) != nil || value.Secret == "" {
		return errors.New("management creation response omitted its one-time key")
	}
	file, err := os.CreateTemp(filepath.Dir(name), ".olp-key-*")
	if err != nil {
		return errors.New("cannot create private key output")
	}
	temporary := file.Name()
	defer os.Remove(temporary)
	if _, err = file.WriteString(value.Secret + "\n"); err != nil {
		file.Close()
		return errors.New("cannot write private key output")
	}
	if err = file.Close(); err != nil {
		return errors.New("cannot finish private key output")
	}
	if err = os.Rename(temporary, name); err != nil {
		return errors.New("cannot publish private key output")
	}
	return nil
}
