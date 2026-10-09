# opencode-officeace-auth

A [Magpie](https://github.com/nicepkg/magpie) / [OpenCode](https://github.com/sst/opencode) provider plugin for **Huawei Cloud OfficeAce (果办 / OfficeClaw)** models.

It implements the full OfficeAce sign-in flow (OAuth 2.0 PKCE + DPoP against Huawei Cloud STS), Huawei request signing (SDK-HMAC-SHA256 + IAM v3 credential exchange), the studio model list, MaaS chat (OpenAI-compatible with Basic auth), and subscription/usage reporting — mirroring the shipped `opencode-codearts-auth` plugin.

- **Zero runtime dependencies** — only Node.js built-ins (`node:crypto`, WebCrypto).
- **Single file** — `index.mjs` exports `OfficeAceAuthPlugin` (the plugin) and `_internal` (for tests).
- **Tests** — `node --test` (35 tests).

## Install

### From source

```bash
git clone <this-repo> D:\Projects\OfficeAce
cd D:\Projects\OfficeAce
node --test          # optional: verify 35/35 pass
```

### Into Magpie / OpenCode

Copy (or symlink) the plugin directory into your Magpie plugins folder, then
register it via `registry-entry.json`:

```jsonc
// registry-entry.json
{
  "replaces": "officeace",
  "providers": ["officeace"]
}
```

Magpie will load `index.mjs`, call `OfficeAceAuthPlugin.config()` to register the
`officeace` provider, and surface a **Sign in to OfficeAce** action. Clicking it
opens the Huawei Cloud authorize URL in your browser; after you sign in, the
plugin polls the OfficeAce backend for the auth code and exchanges it for
temporary AK/SK/security-token credentials.

## Usage

Once signed in:

- **Models** — `officeace:*` models appear in the model picker. Each model's
  `model_auth_info` (MaaS app key/secret) is used for chat; models without MaaS
  auth fall back to SDK-HMAC-SHA256 signed requests.
- **Chat** — OpenAI-compatible Chat Completions at `{model_api_url_base}/v2/chat/completions`.
- **Usage** — the account's credit usage is reported back to Magpie as a usage
  window (`积分` / credits).

## Configuration

All endpoints are env-overridable for testing / self-hosted deployments:

| Env var | Default | Purpose |
|---|---|---|
| `HUAWEI_CLAW_URL` or `OFFICE_CLAW_API_HOST` | `https://agentarts.cn-southwest-2.myhuaweicloud.com` | OfficeAce (claw) base |
| `OAUTH_AUTH_BASE` | `https://auth.huaweicloud.com` | Huawei Cloud auth UI |
| `OAUTH_IAM_BASE_URL` | `https://sts.cn-north-4.myhuaweicloud.com` | STS token endpoint |
| `IAM_URL` | `https://iam.myhuaweicloud.com` | IAM keystone (v3 exchange) |
| `OFFICE_CLAW_IAM_SECURITY_TOKEN_URL` | `{IAM_URL}/v3.0/OS-CREDENTIAL/securitytokens` | IAM v3 securitytokens endpoint |
| `OFFICE_CLAW_CAS_IAM_SECURITY_TOKEN_URL` | (same as above) | CAS IAM v3 endpoint |

No static API key is required — credentials are obtained dynamically via OAuth.

## Scripts

```bash
node --test          # run the 35 unit tests
```

## Project layout

```
OfficeAce/
├── index.mjs              # the plugin (OfficeAceAuthPlugin + _internal)
├── index.test.mjs         # 35 tests (node --test)
├── package.json           # name: opencode-officeace-auth, type: module
├── registry-entry.json    # replaces "officeace", providers: ["officeace"]
├── resources/
│   └── icons/
│       └── huawei.svg     # provider icon
├── DESIGN.md              # design + flow docs
├── LICENSE                # MIT
├── .gitignore
└── .editorconfig
```

## How it works

See [DESIGN.md](./DESIGN.md) for the full design: OAuth flow diagram, signing
algorithm details, endpoint table, and chat routing logic.

## License

MIT
