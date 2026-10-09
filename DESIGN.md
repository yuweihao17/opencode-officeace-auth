# Design — `opencode-officeace-auth`

A Magpie / OpenCode provider plugin for **Huawei Cloud OfficeAce (果办 / OfficeClaw)**
models. It mirrors the shipped CodeArts plugin (`opencode-codearts-auth`) in
structure and conventions: a single `index.mjs` with no runtime dependencies
(only `node:crypto` + WebCrypto built-ins), tests via `node --test`, and an
`_internal` export for unit testing.

## Why a plugin?

OfficeAce serves its models over an OpenAI-compatible Chat Completions API, but
unlike a plain OpenAI provider it does **not** take a static API key. Requests
are authenticated either by:

- **MaaS Basic auth** — a per-model `model_app_key` / `model_app_secret` pair
  carried as `Authorization: Basic base64(key:secret)`, or
- **Huawei SDK-HMAC-SHA256 signed temporary credentials** — AK/SK/security-token
  obtained by signing in to Huawei Cloud with OAuth.

Those temporary credentials come from an **OAuth 2.0 PKCE + DPoP** flow against
Huawei Cloud STS. This plugin implements exactly that flow, mirroring the real
OfficeAce desktop agent (reverse-engineered from the installed app's bundled
`green-package` auth module and `ua-signed-request` signing chunk).

## Authentication flow

```
┌─────────────┐                        ┌──────────────┐
│  magpie     │  authorize()           │  plugin      │
│  opens URL  │ ◄───────────────────── │  (this code) │
└─────────────┘                        └──────┬───────┘
                                             │ 1. POST {claw}/v1/claw/auth/state → {state}
                                             │ 2. build authorize URL (PKCE + DPoP)
                                             │ 3. return {url, callback}
                                             │
   ┌─────────────────┐                      │
   │  Huawei Cloud   │  browser sign-in     │
   │  portal (auth)  │ ◄────────────────────┘
   └────────┬────────┘
            │ user logs in
            ▼
   ┌─────────────────┐  GET /v1/claw/auth/code?state=   ┌───────────────┐
   │  claw backend   │ ──────────────────────────────► │  callback()   │
   │  stores code    │ ◄──────── {code} ────────────── │  polls every  │
   └─────────────────┘                                 │  1.5 s ≤ 300 s │
                                                       └───────┬───────┘
                                                               │ 4. POST {iam}/v1/oauth2/tokens
                                                               │    grant_type=authorization_code
                                                               │    + code_verifier + DPoP proof
                                                               ▼
                                                       ┌───────────────┐
                                                       │  STS answers  │
                                                       │  AK/SK/ST +   │
                                                       │  refresh_token│
                                                       └───────────────┘
```

### PKCE

A random 48-byte base64url `code_verifier` is generated with
`crypto.getRandomValues`. Its S256 `code_challenge` is sent in the authorize URL;
the verifier is sent to the token endpoint with the code.

### DPoP

A fresh ES256 (P-256) key pair is generated per sign-in via
`crypto.subtle.generateKey`. Each token request carries a `DPoP` header holding
a `dpop+jwt` JWS signed with the private key (`htm`, `htu`, `iat`, `jti`). The
private key JWK is persisted in the credential so refresh requests can re-sign
with the same key.

### Credential refresh

`auth.refresh` renews before expiry via `grant_type=refresh_token`, reusing the
stored verifier + DPoP key. On `invalid_grant` / `ExpiredRefreshToken` the error
is tagged `signIn: "expired"` so magpie marks the account for re-auth.

## Request signing

Two algorithms are supported, ported verbatim from the OfficeAce dist's
`ua-signed-request` module (`chunk-XOTX5NN5.js`):

| Algorithm | String-to-sign | Used by |
|---|---|---|
| **SDK-HMAC-SHA256** | `SDK-HMAC-SHA256\n{date}\n{sha256(canonical)}` | model list, subscription, chat fallback |
| **V11-HMAC-SHA256** | `V11-HMAC-SHA256\n{date}\n{scope}\n{sha256(canonical)}` + derived signing key | (SIS session auth — not used by core endpoints) |

### Canonical request

```
METHOD
{canonical-uri}          # RFC-3986 encoded path segments, trailing /
{canonical-query}        # sorted by (key, value), RFC-3986 encoded
{header-lines}           # lowercase-key:value, one per signed header, sorted
{empty}
{signed-headers}         # semicolon-joined, sorted
{payload-hash}           # sha256(body) or "UNSIGNED-PAYLOAD" when preSigned
```

### IAM v3 credential exchange

The OAuth token endpoint issues **IAMv5** credentials. Some endpoints (the
studio model list) require **IAMv3**, obtained by POSTing to
`/v3.0/OS-CREDENTIAL/securitytokens` with the v5 credential signing the request
(body: `{auth:{identity:{methods:["token"],token:{duration_seconds:86400}}}}`).
The plugin caches the v3 credential and refreshes it 10 min before expiry.

### `fetchSigned` (preferV3 + fallback)

Mirrors the dist's `fetchHuaweiSignedWithIamV3Fallback`:
- `preferV3: true` → resolve v3, sign with v3; if v3 unavailable, fall back to v5.
- `preferV3: false` → sign with v5; on 401 `APIG.0301` (v5 rejected), retry with v3.

## Endpoints

| Purpose | Method | URL |
|---|---|---|
| OAuth state | POST | `{claw}/v1/claw/auth/state` → `{state}` |
| Authorize URL | (browser) | `{auth}/authui/v1/oauth2/authorize?{client_id,code_challenge,state,scope,redirect_uri,response_type}` |
| Code polling | GET | `{claw}/v1/claw/auth/code?state=` → `{code}` |
| Token exchange | POST | `{iam}/v1/oauth2/tokens` (grant_type=authorization_code/refresh_token) |
| IAM v3 exchange | POST | `{keystone}/v3.0/OS-CREDENTIAL/securitytokens` |
| Model list | GET | `{claw}/v1/studio/model-services?provider_id=100&page_num=N&page_size=500` |
| Subscribe | POST | `{claw}/v1/studio/maas-model-services/subscribe` |
| Subscription | GET | `{claw}/v1/subscription` (`x-subscription-type: v2`) |
| Usage | GET | `{claw}/v1/subscription/usage` |
| Chat | POST | `{model.api_url}/chat/completions` (OpenAI-compatible) |

## Base URLs (env-overridable)

| Constant | Default | Env var(s) |
|---|---|---|
| Claw base | `https://agentarts.cn-southwest-2.myhuaweicloud.com` | `HUAWEI_CLAW_URL`, `OFFICE_CLAW_API_HOST` |
| Auth base | `https://auth.huaweicloud.com` | `OAUTH_AUTH_BASE` |
| IAM token base | `https://sts.cn-north-4.myhuaweicloud.com` | `OAUTH_IAM_BASE_URL` |
| IAM keystone | `https://iam.myhuaweicloud.com` | `IAM_URL` |
| IAM v3 security tokens | `{keystone}/v3.0/OS-CREDENTIAL/securitytokens` | `OFFICE_CLAW_IAM_SECURITY_TOKEN_URL` |
| Client ID | `pdp5_for_agentarts` | (hardcoded) |
| Redirect URI | `{claw}/v1/claw/auth/callback` | (derived) |
| Region | `cn-southwest-2` | (hardcoded) |

## Chat routing

Each model from `/v1/studio/model-services` may carry `model_auth_info`
(`model_app_key` / `model_app_secret`) and `model_api_url_base`. When present,
the loader's `fetch` wrapper:

1. Looks up the model by id from the request body's `model` field.
2. Rewrites the request URL to `{normalizeMaasBaseUrl(model_api_url_base)}/chat/completions`.
3. Sets `Authorization: Basic base64(key:secret)`.

When the model has no MaaS auth info, the wrapper falls back to SDK-HMAC-SHA256
signing with the account's v5 credential.

`normalizeMaasBaseUrl` trims trailing slashes, ensures an `https://` scheme, and
appends `/v2` if not already present — matching the desktop's
`huawei-maas.js`.

## Model list normalization

Each item from the studio response (`{data: [...], total: N}`) is normalized
mirroring the desktop's `cke()`:

```
{model_name, service_name, api_url, logo, model_series, is_reasoning,
 context_length, is_subscribed, model_auth_info, model_api_url_base}
→ {id, name, baseUrl, icon, modelSeries, isReasoning, contextLength,
   isSubscribed, authInfo, apiBaseUrl}
```

Pagination loops `page_num=1..20` with `page_size=500`, breaking when a page is
short, empty, or the accumulated count reaches `total`.

## Usage

`auth.usage` calls `GET /v1/subscription` (signed, `x-subscription-type: v2`)
and maps `{total_credits, used_credits, plan_name}` to a single magpie usage
window `{name: "积分", used, display, amount, limit, unit: "credits"}`.

## Testing

`node --test` runs 35 tests covering: crypto primitives, PKCE/DPoP, SDK + V11
signing (determinism + header sets), canonical request layout, MaaS URL/auth
normalization, model parsing, the full OAuth flow (state → poll → token
exchange), plugin hooks (config, models, loader, refresh, usage), and the
authorize/callback lifecycle — all with `globalThis.fetch` stubbed via
`options.fetch`.
