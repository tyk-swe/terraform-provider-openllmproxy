# Terraform provider for OpenLLMProxy

A Terraform and OpenTofu provider for the OpenLLMProxy management API.
The provider uses the contract-generated OLP management client, mounted token
files, current caller authority and observed resource ETags. The resource set includes
projects, providers, credential slots, routes, routing policies, guardrails, export sinks, keys,
budget groups, notification destinations, notification rules and upstream MCP servers.

Each resource accepts a `definition` containing the JSON fields of its OLP
creation request. Mutable fields update through the declared API; changes to
immutable creation fields require replacement. IDs and observed ETags are
computed. Removing a nullable field clears it, and equivalent decimal budget
values retain their configured spelling. Import accepts the OLP resource UUID
and discovers its nonsecret definition. Dependent resources and retained
history block deletion with a conflict; reviewed plans cannot overwrite an
external edit made after their observed ETag.

## Connection and secrets

Set `OLP_MANAGEMENT_URL` to the HTTPS installation origin and
`OLP_MANAGEMENT_TOKEN_FILE` to a private mounted management-token file. Loopback
HTTP is supported for development. The file is reread on every call. The
provider stores the path rather than the token value; use a token with only the
scopes required by the managed resources. Project administration requires an
installation-wide `manage_projects` token whose creator remains an owner;
budget and notification administration use the corresponding `keys` or
installation `settings` scopes.

Credential values are rejected from `definition`. Provider, slot, sink, MCP and notification secrets
use the separate `secret` write-only attribute and a positive `secret_version`
change counter. Supply the value through an ephemeral variable, and increment
the counter when rotating it. Terraform 1.11+ and OpenTofu 1.11+ support this
protocol; the qualified versions are Terraform 1.16.5 and OpenTofu 1.13.1.

```hcl
variable "signing_secret" {
  type      = string
  sensitive = true
  ephemeral = true
}

resource "openllmproxy_project" "example" {
  definition = jsonencode({ name = "Production" })
}

resource "openllmproxy_notification_destination" "example" {
  definition = jsonencode({
    name       = "Budget alerts"
    project_id = openllmproxy_project.example.id
    url        = "https://alerts.example.com/olp"
    enabled    = true
  })
  secret         = var.signing_secret
  secret_version = 1
}
```

## Development and qualification

Build with Go 1.27.1+:

```sh
go test -race ./...
go vet ./...
mkdir -p .local/plugin
go build -o .local/plugin/terraform-provider-openllmproxy .
./scripts/install-tools.sh
```

Use a Terraform/OpenTofu CLI configuration with a `dev_overrides` entry for
`registry.terraform.io/tyk-swe/openllmproxy` pointing to the absolute plugin
directory. Specify that same provider source in `required_providers`; a
development override loads the built executable without registry installation.

The integration-tagged acceptance suite requires `OLP_TEST_DATABASE_URL` and
`OLP_TEST_VALKEY_URL` pointing to disposable PostgreSQL 18 and Valkey services,
plus absolute executable paths in `OLP_TEST_BINARY`,
`OLP_TEST_PROVIDER_BINARY`, `OLP_TEST_TERRAFORM_BINARY` and
`OLP_TEST_TOFU_BINARY`. Run:

```sh
go test -race -count=1 -tags=integration -timeout=15m -v ./tests/acceptance
```

Each fixture creates an isolated database, owner, management token, encryption
keys and live OLP process. Both real engines exercise plan, create, update,
import and destroy, verify concurrent-edit refusal, and check that ephemeral
signing values never enter saved plans or state. Missing service configuration
fails explicitly. CI builds OLP from the same immutable module version used by
the generated SDK and runs these checks against disposable services.

API keys use `openllmproxy_key`. The provider keeps editable ceilings distinct
from accrued spend and revokes keys on destroy so retained accounting stays
intact. An optional absolute `secret_file` atomically captures the generated
one-time key in a 0600 file; only the destination path enters state. The
provider records the created identity before reporting an output error, allowing
a failed capture to be reconciled or destroyed. Changing the destination
requires replacement. Import cannot recover a one-time key: omit `secret_file`
when adopting an existing key. Revocation leaves the output file in place for
the operator to remove; its credential is then unusable.

## Providers and credential slots

`openllmproxy_provider` manages the draft configuration. Use the write-only
`secret` and `secret_version` for its credential; incrementing the counter
validates a new immutable version against the committed draft configuration.
A failed validation retains committed configuration and the previous successful
counter so the next plan can reconcile the partial result. Optional `model` and
`display_name` seed inventory at creation and are omitted when importing an
existing provider. Normalized defaults do not add fields to your definition.

`openllmproxy_credential_slot` requires `provider_id` and accepts the slot's own
fields as its definition, with a separate write-only secret. New slots use an
observed collection ETag; existing slots use independent ETags, so sibling
updates do not conflict. Import uses `PROVIDER_UUID/SLOT_UUID`. A pinned
`credential_reference` may replace plaintext in either definition. References
are public metadata; resolved values never enter state.

Deleting a nondefault draft slot preserves its immutable credential versions
and published bindings. An unused draft provider can be deleted; publication,
route references, provider-specific prices and retained history cause conflicts.
Dependent slot deletions report atomic parent transitions. The client follows
only a contiguous chain of its own writes when deleting the provider; an
intervening external edit remains a conflict, including for a saved destroy plan.

`openllmproxy_route` manages published routes. Create and replacement validate a
fresh source draft and publish an immutable revision in one transaction;
independent console drafts and the current routing policy remain intact. Targets
retain only selected facts in state. Import uses the route UUID and canonical
provider-model IDs. The slug is immutable; changing it requires replacement.
Destroy retires the route while preserving its slug, revisions and accounting
history. A retired slug cannot be reused by a new resource: restore or import its
existing identity when intentional. Saved plans cannot overwrite a concurrent
external publication.

## Scoped routing policies

`openllmproxy_routing_policy` takes `scope`, `scope_id`, and a JSON policy
`definition`. Supported scopes are `installation` (nil UUID), `api-key`, and
`route-draft`; their ordinary settings, key, or configuration permissions apply.
Import uses `SCOPE/UUID`. Existing explicit policies must be imported before
management; a default policy is not treated as an existing override.

Policy updates replace the complete policy, so omitting a constraint resets it
to the default. Destroy removes the explicit override and preserves a fresh
conditional-write observation. Draft changes become live upon activation.
The provider coordinates a key and its policy through proven writes from the
same apply. External parent or policy changes still invalidate reviewed plans.

```hcl
resource "openllmproxy_routing_policy" "client" {
  scope    = "api-key"
  scope_id = openllmproxy_key.client.id
  definition = jsonencode({
    allowed_strategies = ["weighted"]
  })
}
```

## Named guardrails

`openllmproxy_guardrail` accepts a project UUID, name, `builtin.regex` type and
bounded content-policy object in its JSON `definition`. Updates append immutable
policy revisions and require the observed ETag; import uses the guardrail UUID.
Destroy retires the active definition and retains policy history, including its
project boundary. `read`/`configure` authority remains project-scoped.

Use `jsondecode(openllmproxy_guardrail.filter.definition).policy` as a route's
`content_policy` inside `jsonencode`. Terraform then reviews and publishes a
selected copy through the route's ordinary conditional API. Existing route
revisions retain their copies when a named definition changes or retires.
A saved plan refuses an external definition edit before changing the dependent
route. Retained history can prevent deletion of the owning project.

## Content-free export sinks

`openllmproxy_sink` manages an installation or project HTTPS JSON destination
with a conditional UUID/ETag lifecycle. Its definition selects name, `type =
"https"`, destination, streams, enabled state and optional project UUID. Supported
streams are requests, attempts, guardrail_decisions and installation-only audit.
Project writes require keys/project-change authority; installation writes require
settings. Endpoint validation and every dial use provider egress policy.

Use the sensitive write-only `secret` attribute and increment `secret_version`
when replacing HMAC signing bytes. Ephemeral inputs keep values out of saved
plans and state, including their JSON representations. UUID imports reconstruct
nonsecret definitions; credential values cannot be imported. The installation's
worker sends durable, content-free events with stable IDs, exact-byte signatures,
bounded retries and expiry-gap counts. Delivery counters never alter the resource
ETag or definition.

Destroy retires the sink, cancels pending work and removes signing material;
identity and history remain. Retained project-owned sinks can prevent project
deletion. Saved plans refuse external edits. Configuration promotion moves only
logical definitions and separately supplied destination signing bindings, not
queued events, counters or local secret values. See the gateway's
[export sink guide](https://github.com/tyk-swe/olp/blob/6861b35683449193f03189c28080f2b09453d03c/docs/export-sinks.md).

## Certified upstream MCP servers

`openllmproxy_mcp_server` manages a project-owned Streamable HTTP registration.
Its definition contains name, project UUID, transport, endpoint and enabled state.
Create/update certifies a bounded, credential-safe tool catalog outside database
locks, then repeats authority and ETag checks before appending an immutable
revision. Reads use the approved catalog without contacting the upstream.

Static bearer values use sensitive write-only `secret`, an ephemeral input and
positive `secret_version`; values never enter saved plans or state. UUID imports
reconstruct nonsecret configuration. An upstream change requires an explicit
reviewed update; a foreign registration change invalidates a saved plan. Destroy
retires the registration and removes authentication material while preserving
old catalogs and the project boundary. The management resource certifies catalogs
without invoking upstream tools. See the gateway's
[registration guide](https://github.com/tyk-swe/olp/blob/6861b35683449193f03189c28080f2b09453d03c/docs/mcp-servers.md).
