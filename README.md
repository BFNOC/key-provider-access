# CPA Key Provider Access

`key-provider-access` is a local CLIProxyAPI plugin derived from the layout and management UI of `key-model-access` v0.1.3. It keeps CPA's built-in downstream API-key authentication and applies a per-key allow/deny policy to upstream credential profiles instead of model names.

Profiles include both OAuth credentials and API-key-backed providers. Policies store CPA's stable auth IDs, never OAuth tokens or upstream API keys.

## Behavior

- CPA authenticates a downstream key and supplies `Metadata.caller_scope`.
- A key without a policy may use every eligible upstream profile.
- `deny_profiles` wins over `allow_profiles`.
- A non-empty `allow_profiles` list is a whitelist.
- An empty `allow_profiles` list allows every profile not matched by `deny_profiles`.
- `*` matches any number of characters and `?` matches one character.
- The scheduler chooses only among allowed candidates and round-robins eligible candidates.
- If no offered candidate matches a non-empty allow list, the request is denied. This covers an
  allowed profile that is cooling down, disabled, outranked by another priority tier, or whose ID
  changed because its API key, base URL, proxy URL, prefix, headers, or provider name was edited.
  Other profiles are never adopted in its place.
- Each denial is recorded in the status `runtime_warning` / `runtime_warning_detail` fields and shown
  on the dashboard overview with the key fingerprint, provider, model, offered profile IDs (emails
  masked), count, and time. It stays until the policy is saved or reloaded. The first denial for
  each key, provider, and model combination is also written to the CPA process log.
- The dashboard never adds, removes, or restores rules on its own. Rules whose profiles are missing
  from the catalog stay in the policy and are counted in a notice; a key whose allowed profiles
  have all disappeared stays denied and is flagged until the operator picks replacements.
- Removing a key's last allowed profile in the dashboard sets `deny_profiles = ["*"]` instead of
  leaving an empty allow list, which would mean allow-all.
- If the after-auth check sees a legacy-capable API-key profile that this plugin's scheduler never
  evaluated (CPA Home mode or another active scheduler plugin) and the key has exact deny rules of
  the same kind, the request is denied because a legacy-format deny cannot be verified.
- Legacy Gemini, Gemini Interactions, Claude, Codex, and xAI API-key profile IDs from CPA's
  pre-v7.2.146 format are matched against current candidates using transient attributes. This
  preserves existing allow/deny rules across CPA's ID-format change without persisting credentials
  or silently allowing a different key.
- The after-auth interceptor verifies the selected auth ID before an upstream executor receives the request.
- Missing identity, missing selected-auth metadata, or invalid policy state fails closed whenever policies exist.

The scheduler receives CPA's currently eligible, highest-priority candidate tier. An allow list cannot promote a lower CPA priority tier that the host did not offer. CPA Home mode currently bypasses plugin schedulers; the after-auth check still prevents a disallowed profile from being used, but it cannot reroute that request.

Only one scheduler plugin is active in CPA (the highest-priority enabled scheduler). Configure plugin priorities deliberately if another scheduler plugin is enabled.

## Configuration

```yaml
plugins:
  enabled: true
  dir: "plugins"
  configs:
    key-provider-access:
      enabled: true
      priority: 100
      version: 2
      policies: []
```

The Web UI is available at:

```text
/v0/resource/plugins/key-provider-access/settings
```

It reuses the same-origin CPAMC management session, reads downstream CPA keys to derive caller scopes, and builds a profile catalog from CPA's read-only auth/config management endpoints. Provider secrets are used only transiently to reproduce CPA's stable auth IDs and are not written to plugin state, DOM, browser storage, or URLs.

The panel identifies each downstream key with a masked head-and-tail display; the middle of the full key remains hidden. Full downstream keys are not persisted.

Allow and deny profile choices are visually dimmed when they overlap, but remain clickable: choosing one removes the conflicting rule from the opposite side. Clicking an individual profile while `*` is active expands the wildcard into explicit current profiles with that profile excluded.

On first use, the UI creates `plugins/key-provider-access/config.toml` and patches only this plugin's `policy_file` setting. Policy updates use revision ETags and atomic file replacement.

## Policy schema

```toml
version = 2

[[policies]]
caller_scope = "f7291f3315e5ab0d3c02015a081879d748693f231d8370b43f38f57be991734a"
allow_profiles = ["codex:apikey:abc123def456", "oauth-profile-id"]
deny_profiles = ["*-retired"]
```

Use the Web UI to derive caller scopes and choose current profile IDs. Do not put raw downstream keys, OAuth material, or provider API keys in policy files.

## Build and test

```bash
make check
make build
```

The Linux amd64 output is `dist/key-provider-access.so`. Install it as `plugins/linux/amd64/key-provider-access-v0.1.0.so` (or the unsuffixed name) and enable the matching `key-provider-access` config entry.

## Management API

- `GET /v0/management/plugins/key-provider-access/status`
- `GET/PUT /v0/management/plugins/key-provider-access/policies`
- `POST /v0/management/plugins/key-provider-access/reload`
- `POST /v0/management/plugins/key-provider-access/initialize-storage`

All routes use CPA management authentication. Status output never includes caller scopes or credentials.
