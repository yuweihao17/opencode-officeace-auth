// AI生成
// Unit tests for the OfficeAce OAuth plugin. Run with: node --test
//
// These tests exercise the pieces magpie calls (_internal helpers) and the
// hooks the plugin returns, with the network stubbed out via `options.fetch`.

import test from "node:test"
import assert from "node:assert/strict"
import { mkdtemp, mkdir, writeFile, rm } from "node:fs/promises"
import { tmpdir } from "node:os"
import { join } from "node:path"

import { OfficeAceAuthPlugin, _internal as x } from "./index.mjs"

// An override pointing at a directory with no routing state, so tests do not
// read the developer machine's real ~/.office-claw routing credentials.
const NO_ROUTING_ENV = { OFFICEACE_ROUTING_DIR: join(tmpdir(), "officeace-no-routing") }

const buf = (s) => new TextEncoder().encode(s)

// ---- crypto primitives -----------------------------------------------------

test("sha256Hex matches the known SHA-256 of the empty string", async () => {
  assert.equal(
    await x.sha256Hex(new Uint8Array()),
    "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
  )
})

test("hmacSha256Hex matches RFC 4231 test case 2", async () => {
  assert.equal(
    await x.hmacSha256Hex(buf("Jefe"), buf("what do ya want for nothing?")),
    "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843",
  )
})

test("generatePkcePair derives the S256 challenge from the verifier", async () => {
  const pkce = await x.generatePkcePair()
  assert.match(pkce.codeVerifier, /^[A-Za-z0-9_-]{64}$/)
  const expected = x.b64url(new Uint8Array(await crypto.subtle.digest("SHA-256", buf(pkce.codeVerifier))))
  assert.equal(pkce.codeChallenge, expected)
})

test("signDpopJws produces a verifiable ES256 dpop+jwt", async () => {
  const keyPair = await x.generateDpopKeyPair()
  const jws = await x.signDpopJws(keyPair, "POST", "https://sts.example.com/tokens")
  const [h, p, s] = jws.split(".")
  assert.equal(jws.split(".").length, 3)

  const header = JSON.parse(Buffer.from(h, "base64url").toString())
  assert.equal(header.alg, "ES256")
  assert.equal(header.typ, "dpop+jwt")
  assert.deepEqual(header.jwk, keyPair.publicKeyJwk)

  const payload = JSON.parse(Buffer.from(p, "base64url").toString())
  assert.equal(payload.htm, "POST")
  assert.equal(payload.htu, "https://sts.example.com/tokens")
  assert.equal(typeof payload.iat, "number")
  assert.equal(typeof payload.jti, "string")

  const key = await crypto.subtle.importKey(
    "jwk", keyPair.publicKeyJwk, { name: "ECDSA", namedCurve: "P-256" }, false, ["verify"],
  )
  const ok = await crypto.subtle.verify(
    { name: "ECDSA", hash: "SHA-256" }, key, Buffer.from(s, "base64url"), buf(`${h}.${p}`),
  )
  assert.ok(ok, "the DPoP signature must verify against the advertised public key")
})

// ---- SDK-HMAC-SHA256 / V11-HMAC-SHA256 signing -----------------------------

test("buildCanonicalRequest lays out the canonical request with sorted query + encoded path", () => {
  const url = new URL("https://example.com/path?b=2&a=1")
  const headers = { host: "example.com", "x-sdk-content-sha256": "H", "x-sdk-date": "D", "x-security-token": "ST" }
  const keys = Object.keys(headers).sort()
  const expected = [
    "GET",
    "/path/",
    "a=1&b=2",
    "host:example.com\nx-sdk-content-sha256:H\nx-sdk-date:D\nx-security-token:ST",
    "",
    "host;x-sdk-content-sha256;x-sdk-date;x-security-token",
    "H",
  ].join("\n")
  assert.equal(x.buildCanonicalRequest("GET", url, headers, keys, "H"), expected)
})

test("buildSignedHeaders signs a GET with the expected SDK-HMAC-SHA256 header set", async () => {
  const signed = await x.buildSignedHeaders({
    method: "GET", url: "https://example.com/path",
    credential: { accessKey: "AK", secretKey: "SK", securityToken: "ST" },
    bodyText: "", dateOverride: new Date(Date.UTC(2026, 0, 1, 0, 0, 0)),
  })
  assert.equal(signed["X-Sdk-Date"], "20260101T000000Z")
  assert.equal(signed["X-Security-Token"], "ST")
  assert.equal(signed["Host"], "example.com")
  // GET carries no content-type; x-sdk-content-sha256 is only signed when preSigned.
  assert.equal(signed["Content-Type"], undefined)
  assert.match(
    signed["Authorization"],
    /^SDK-HMAC-SHA256 Access=AK, SignedHeaders=host;x-sdk-date;x-security-token, Signature=[0-9a-f]{64}$/,
  )
})

test("buildSignedHeaders includes content-type and an extra header in a signed POST", async () => {
  const signed = await x.buildSignedHeaders({
    method: "POST", url: "https://example.com/api/v2/chat/completions",
    credential: { accessKey: "AK", secretKey: "SK", securityToken: "ST" },
    bodyText: '{"model":"glm-4.6"}', contentType: "application/json",
    headers: { "x-subscription-type": "v2" }, dateOverride: new Date(Date.UTC(2026, 0, 1, 0, 0, 0)),
  })
  const auth = signed["Authorization"]
  assert.match(auth, /SignedHeaders=content-type;host;x-sdk-date;x-security-token;x-subscription-type,/)
  assert.equal(signed["Content-Type"], "application/json")
  assert.equal(signed["x-subscription-type"], "v2")
})

test("buildSignedHeaders is deterministic for a fixed date stamp", async () => {
  const args = {
    method: "POST", url: "https://example.com/x",
    credential: { accessKey: "AK", secretKey: "SK", securityToken: "ST" },
    bodyText: "body", dateOverride: new Date(Date.UTC(2026, 0, 1, 0, 0, 0)),
  }
  const a = await x.buildSignedHeaders(args)
  const b = await x.buildSignedHeaders(args)
  assert.equal(a["Authorization"], b["Authorization"])
})

test("buildSignedHeaders produces a V11-HMAC-SHA256 Authorization with credential scope", async () => {
  const signed = await x.buildSignedHeaders({
    method: "GET", url: "https://example.com/path",
    credential: { accessKey: "AK", secretKey: "SK", securityToken: "ST" },
    bodyText: "", algorithm: x.ALGO_V11, regionId: x.REGION_ID,
    dateOverride: new Date(Date.UTC(2026, 0, 1, 0, 0, 0)),
  })
  assert.match(
    signed["Authorization"],
    /^V11-HMAC-SHA256 Credential=AK\/20260101\/cn-southwest-2\/apic, SignedHeaders=[^,]+, Signature=[0-9a-f]+$/,
  )
  // V11 must be deterministic too.
  const again = await x.buildSignedHeaders({
    method: "GET", url: "https://example.com/path",
    credential: { accessKey: "AK", secretKey: "SK", securityToken: "ST" },
    bodyText: "", algorithm: x.ALGO_V11, regionId: x.REGION_ID,
    dateOverride: new Date(Date.UTC(2026, 0, 1, 0, 0, 0)),
  })
  assert.equal(signed["Authorization"], again["Authorization"])
})

test("buildSignedHeaders returns null when credentials are incomplete", async () => {
  const signed = await x.buildSignedHeaders({
    method: "GET", url: "https://example.com/path",
    credential: { accessKey: "", secretKey: "SK", securityToken: "ST" }, bodyText: "",
  })
  assert.equal(signed, null)
})

// ---- helpers ---------------------------------------------------------------

test("normalizeMaasBaseUrl appends /v2 and strips trailing slashes", () => {
  assert.equal(x.normalizeMaasBaseUrl("https://maas.example.com/"), "https://maas.example.com/v2")
  assert.equal(x.normalizeMaasBaseUrl("https://maas.example.com/v2/"), "https://maas.example.com/v2")
  assert.equal(x.normalizeMaasBaseUrl("maas.example.com"), "https://maas.example.com/v2")
})

test("parseModelInfo maps the studio item shape and passes through MaaS auth", () => {
  const mi = x.parseModelInfo({
    model_name: "glm-4.6",
    service_name: "GLM-4.6",
    api_url: "https://maas.example.com",
    model_series: "glm",
    is_reasoning: false,
    context_length: "128000",
    is_subscribed: true,
    model_auth_info: { model_app_key: "K", model_app_secret: "S" },
    model_api_url_base: "https://maas.example.com",
  })
  assert.deepEqual(mi, {
    id: "glm-4.6", name: "GLM-4.6", baseUrl: "https://maas.example.com",
    modelSeries: "glm", isReasoning: false, contextLength: "128000", isSubscribed: true,
    authInfo: { model_app_key: "K", model_app_secret: "S" },
    apiBaseUrl: "https://maas.example.com",
  })
  assert.equal(x.parseModelInfo({}), undefined)
  assert.equal(x.parseModelInfo({ model_name: "", service_name: "" }), undefined)
})

test("credentialOf round-trips a credential stored in the access field", async () => {
  const keyPair = await x.generateDpopKeyPair()
  const cred = x.credentialFromTokenResponse(
    { credentials: { access_key_id: "AK", secret_access_key: "SK", security_token: "ST", expiration: "2030-01-01T00:00:00Z" }, refresh_token: "R" },
    "verifier",
    keyPair,
  )
  const auth = { type: "oauth", access: JSON.stringify(cred), refresh: "R" }
  const back = x.credentialOf(auth)
  assert.equal(back.access_key_id, "AK")
  assert.equal(back.refresh_token, "R")
  assert.equal(back.code_verifier, "verifier")
  assert.deepEqual(back.dpop_private_key_jwk, keyPair.privateKeyJwk)
  assert.equal(x.credentialOf({ type: "api", key: "k" }), null)
})

test("expiresFromCredential parses the STS expiration or falls back to +1d", () => {
  assert.equal(x.expiresFromCredential({ expires_at: "2030-01-01T00:00:00Z" }), Date.parse("2030-01-01T00:00:00Z"))
  const soon = x.expiresFromCredential({})
  assert.ok(soon > Date.now() + 86_000_000 && soon <= Date.now() + 86_400_000)
})

test("buildOAuthLoginUrl carries the PKCE + DPoP parameters the portal expects", () => {
  const url = new URL(x.buildOAuthLoginUrl("https://auth.huaweicloud.com", { codeChallenge: "CH" }, "S", "https://agentarts.example.com/v1/claw/auth/callback"))
  assert.equal(url.origin + url.pathname, "https://auth.huaweicloud.com/authui/v1/oauth2/authorize")
  const q = url.searchParams
  assert.equal(q.get("client_id"), x.DEFAULT_CLIENT_ID)
  assert.equal(q.get("code_challenge"), "CH")
  assert.equal(q.get("code_challenge_method"), "SHA-256")
  assert.equal(q.get("state"), "S")
  assert.equal(q.get("scope"), "openid")
  assert.equal(q.get("response_type"), "code")
  assert.equal(q.get("redirect_uri"), "https://agentarts.example.com/v1/claw/auth/callback")
})

test("formatCredit compacts large numbers in Chinese", () => {
  assert.equal(x.formatCredit(999), "999")
  assert.equal(x.formatCredit(12345), "1.2万")
  assert.equal(x.formatCredit(200_000_000), "2.0亿")
})

test("buildMaasAuthorization builds a Basic header from app key/secret", () => {
  assert.equal(x.buildMaasAuthorization({ model_app_key: "K", model_app_secret: "S" }), `Basic ${Buffer.from("K:S").toString("base64")}`)
  assert.equal(x.buildMaasAuthorization({ model_app_key: "", model_app_secret: "S" }), null)
  assert.equal(x.buildMaasAuthorization(undefined), null)
})

test("resolveModelChatConfig normalizes the base URL and carries the Authorization", () => {
  const cfg = x.resolveModelChatConfig({ authInfo: { model_app_key: "K", model_app_secret: "S" }, apiBaseUrl: "https://maas.example.com/" })
  assert.equal(cfg.baseUrl, "https://maas.example.com/v2")
  assert.equal(cfg.authorization, `Basic ${Buffer.from("K:S").toString("base64")}`)
  assert.equal(x.resolveModelChatConfig({ authInfo: { model_app_key: "", model_app_secret: "" } }), null)
  assert.equal(x.resolveModelChatConfig(undefined), null)
})

// ---- usage / subscription --------------------------------------------------

test("usageFromSubscription maps credits to a single window", () => {
  const usage = x.usageFromSubscription({ total_credits: 1000, used_credits: 400, plan_name: "企业版" })
  assert.equal(usage.plan, "企业版")
  assert.equal(usage.signIn, "kept")
  assert.deepEqual(usage.windows, [{
    name: "积分", used: 40, display: "400 / 1000", amount: 400, limit: 1000, unit: "credits",
  }])
})

test("usageFromSubscription reports no credit plan when every bucket is empty", () => {
  const usage = x.usageFromSubscription({ total_credits: 0, used_credits: 0 })
  assert.deepEqual(usage.windows, [])
  assert.equal(usage.error, "该账号无积分额度")
})

test("usageFromSubscription surfaces a business error code", () => {
  const usage = x.usageFromSubscription({ code: 500, message: "boom" })
  assert.equal(usage.error, "boom")
})

test("usageFromSubscription reads the desktop's nested skus/quotas shape", () => {
  const usage = x.usageFromSubscription({
    subscribe_status: "SUBSCRIBED",
    skus: [{ sku_name: "OfficeAce 标准版", quotas: [{ sku_attr_code: "officeace_points", sku_value: 500000, current_value: 121000 }] }],
  })
  assert.equal(usage.plan, "OfficeAce 标准版")
  assert.equal(usage.signIn, "kept")
  assert.deepEqual(usage.windows, [{
    name: "积分", used: (121000 / 500000) * 100, display: "12.1万 / 50.0万", amount: 121000, limit: 500000, unit: "credits",
  }])
})

test("usageFromSubscription separates bonus credits into their own window", () => {
  const usage = x.usageFromSubscription({
    skus: [{ quotas: [{ sku_attr_code: "officeace_points", sku_value: 1000, current_value: 100 }] }],
    bonus_skus: [{ quotas: [{ sku_attr_code: "officeace_points", sku_value: 500, current_value: 0 }] }],
  })
  assert.deepEqual(usage.windows.map((w) => w.name), ["积分", "赠送积分"])
  assert.equal(usage.windows[0].display, "100 / 1000")
  assert.equal(usage.windows[1].display, "0 / 500")
})

test("usageFromSubscription honours the -1 unlimited marker", () => {
  const usage = x.usageFromSubscription({ skus: [{ quotas: [{ sku_attr_code: "officeace_points", sku_value: -1 }] }] })
  assert.deepEqual(usage.windows, [{ name: "积分", used: 0, display: "不限量", amount: 0, limit: 0, unit: "credits" }])
})

test("usageFromSubscription reports no credits for an unsubscribed account", () => {
  const usage = x.usageFromSubscription({ domain_id: "d", subscribe_status: "UNSUBSCRIBED" })
  assert.deepEqual(usage.windows, [])
  assert.equal(usage.error, "该账号无积分额度")
})

test("subscriptionOrigin prefers the local model gateway and falls back to the claw base", async () => {
  await withRoutingFixture(async (env) => {
    assert.equal(await x.subscriptionOrigin(env), "https://modelgw-0004.officeace.cn-southwest-2.huaweicloud-agentarts.com")
  })
  assert.equal(await x.subscriptionOrigin({ OFFICEACE_ROUTING_DIR: join(tmpdir(), "officeace-missing") }), x.DEFAULT_CLAW_BASE)
})

// ---- remote model list -----------------------------------------------------

const modelServicesBody = JSON.stringify({
  data: [
    { model_name: "glm-4.6", service_name: "GLM-4.6", api_url: "https://maas.example.com", is_subscribed: true,
      model_auth_info: { model_app_key: "K", model_app_secret: "S" }, model_api_url_base: "https://maas.example.com" },
    { model_name: "deepseek-v3.1", service_name: "DeepSeek V3.1", api_url: "https://maas2.example.com" },
  ],
  total: 2,
})

function modelServicesFetcher(seen) {
  return async (url, init) => {
    const u = String(url)
    seen.push({ url: u, auth: new Headers(init?.headers).get("authorization") })
    if (u.includes("/v3.0/OS-CREDENTIAL/securitytokens")) return new Response("{}", { status: 404 })
    if (u.includes("/v1/studio/model-services")) return new Response(modelServicesBody, { status: 200 })
    return new Response("", { status: 404 })
  }
}

test("fetchRemoteModels paginates and normalizes the studio response", async () => {
  const seen = []
  const models = await x.fetchRemoteModels(
    { access_key_id: "AK", secret_access_key: "SK", security_token: "ST", project_id: "" },
    modelServicesFetcher(seen),
    {},
  )
  assert.deepEqual(models.map((m) => m.id), ["glm-4.6", "deepseek-v3.1"])
  assert.equal(models[0].authInfo.model_app_key, "K")
  // Every model-services request is SDK-HMAC-SHA256 signed.
  assert.ok(seen.every((s) => String(s.auth).startsWith("SDK-HMAC-SHA256")))
})

// ---- plugin hooks ----------------------------------------------------------

function makeAuth(cred) {
  return { type: "oauth", access: JSON.stringify(cred), refresh: cred.refresh_token, expires: x.expiresFromCredential(cred) }
}

async function makeCred() {
  const keyPair = await x.generateDpopKeyPair()
  return x.credentialFromTokenResponse(
    { credentials: { access_key_id: "AK", secret_access_key: "SK", security_token: "ST", expiration: "2030-01-01T00:00:00Z" }, refresh_token: "R" },
    "verifier",
    keyPair,
  )
}

test("plugin exposes config, provider.models, and an oauth auth method", async () => {
  const plugin = await OfficeAceAuthPlugin({ client: {} }, {})
  assert.equal(typeof plugin.config, "function")
  assert.equal(plugin.provider.id, "officeace")
  assert.equal(plugin.auth.provider, "officeace")
  assert.equal(plugin.auth.methods.length, 1)
  assert.equal(plugin.auth.methods[0].type, "oauth")

  const config = {}
  await plugin.config(config)
  const p = config.provider.officeace
  assert.equal(p.npm, "@ai-sdk/openai-compatible")
  assert.ok(p.api)
  // @ai-sdk/openai-compatible throws LoadAPIKeyError without a non-empty key.
  assert.equal(p.options.apiKey, "officeace-session")
  assert.ok(p.models["glm-4.6"])
})

test("provider.models returns the account's live list", async () => {
  const cred = await makeCred()
  const plugin = await OfficeAceAuthPlugin({ client: {} }, { fetch: modelServicesFetcher([]) })
  const provider = { models: { "glm-4.6": { name: "GLM-4.6", limit: { context: 0, output: 0 } } } }
  const models = await plugin.provider.models(provider, { auth: makeAuth(cred) })
  assert.deepEqual(Object.keys(models).sort(), ["deepseek-v3.1", "glm-4.6"])
  // The MaaS model carries a per-model api base URL.
  assert.equal(models["glm-4.6"].api, "https://maas.example.com/v2")
})

test("provider.models falls back to the catalog when unsigned", async () => {
  const plugin = await OfficeAceAuthPlugin({ client: {} }, {})
  const provider = { models: { "glm-4.6": {} } }
  assert.deepEqual(await plugin.provider.models(provider, {}), provider.models)
})

test("loader authenticates a MaaS chat request with Basic auth and rewrites the URL", async () => {
  const cred = await makeCred()
  const seen = []
  const fetcher = async (url, init) => {
    const u = String(url)
    seen.push({ url: u, init })
    if (u.includes("/v3.0/OS-CREDENTIAL/securitytokens")) return new Response("{}", { status: 404 })
    if (u.includes("/v1/studio/model-services")) return new Response(modelServicesBody, { status: 200 })
    if (u.includes("/chat/completions")) return new Response(JSON.stringify({ choices: [] }), { status: 200 })
    return new Response("", { status: 404 })
  }
  const plugin = await OfficeAceAuthPlugin({ client: {} }, { fetch: fetcher })
  const loaded = await plugin.auth.loader(async () => makeAuth(cred))
  // The SDK requires an apiKey field; the real auth is applied by the wrapper.
  assert.equal(loaded.apiKey, "officeace-session")

  await loaded.fetch("https://agentarts.example.com/v2/chat/completions", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ model: "glm-4.6", messages: [] }),
  })

  const chatCall = seen.find((s) => s.url.includes("/chat/completions"))
  assert.ok(chatCall, "a chat request was made")
  // The URL was rewritten to the model's MaaS base.
  assert.equal(chatCall.url, "https://maas.example.com/v2/chat/completions")
  const headers = new Headers(chatCall.init.headers)
  assert.match(headers.get("authorization"), /^Basic /)
  assert.equal(headers.get("lang"), "en")
  assert.ok(headers.get("chat-id"))
  assert.ok(headers.get("session-id"))
})

test("loader signs a non-MaaS chat request with SDK-HMAC-SHA256", async () => {
  const cred = await makeCred()
  const seen = []
  const fetcher = async (url, init) => {
    const u = String(url)
    seen.push({ url: u, init })
    if (u.includes("/v3.0/OS-CREDENTIAL/securitytokens")) return new Response("{}", { status: 404 })
    if (u.includes("/v1/studio/model-services")) return new Response(modelServicesBody, { status: 200 })
    if (u.includes("/chat/completions")) return new Response(JSON.stringify({ choices: [] }), { status: 200 })
    return new Response("", { status: 404 })
  }
  const plugin = await OfficeAceAuthPlugin({ client: {} }, { fetch: fetcher, env: NO_ROUTING_ENV })
  const loaded = await plugin.auth.loader(async () => makeAuth(cred))

  // deepseek-v3.1 has no model_auth_info → signed fallback.
  await loaded.fetch("https://agentarts.example.com/v2/chat/completions", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ model: "deepseek-v3.1", messages: [] }),
  })

  const chatCall = seen.find((s) => s.url.includes("/chat/completions"))
  const headers = new Headers(chatCall.init.headers)
  assert.match(headers.get("authorization"), /^SDK-HMAC-SHA256 Access=AK,/)
})

test("loader resolves the per-model MaaS auth when the body is a Request", async () => {
  const cred = await makeCred()
  const seen = []
  const fetcher = async (url, init) => {
    const u = String(url)
    seen.push({ url: u, init })
    if (u.includes("/v3.0/OS-CREDENTIAL/securitytokens")) return new Response("{}", { status: 404 })
    if (u.includes("/v1/studio/model-services")) return new Response(modelServicesBody, { status: 200 })
    if (u.includes("/chat/completions")) return new Response(JSON.stringify({ choices: [] }), { status: 200 })
    return new Response("", { status: 404 })
  }
  const plugin = await OfficeAceAuthPlugin({ client: {} }, { fetch: fetcher })
  const loaded = await plugin.auth.loader(async () => makeAuth(cred))

  // No `init.body`: the host handed us a Request, as fetch(Request) allows.
  const request = new Request("https://agentarts.example.com/v2/chat/completions", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ model: "glm-4.6", messages: [] }),
  })
  await loaded.fetch(request)

  const chatCall = seen.find((s) => s.url.includes("/chat/completions"))
  assert.equal(chatCall.url, "https://maas.example.com/v2/chat/completions")
  assert.match(new Headers(chatCall.init.headers).get("authorization"), /^Basic /)
})

// ---- account-level MaaS auth (client-permission-validate) -------------------

const permissionBody = JSON.stringify({
  code: 0,
  model_info: {
    model_api_url_base: "https://maas-acct.example.com/",
    model_auth_info: { model_app_key: "AK_APP", model_app_secret: "SK_APP" },
  },
})

// A studio list whose items carry NO model_auth_info, as the live API returns.
const bareStudioBody = JSON.stringify({
  data: [{ model_name: "glm-5.2", service_name: "GLM-5.2", api_url: "https://maas.example.com" }],
  total: 1,
})

test("fetchModelInfo signs a GET to the permission endpoint and returns model_info", async () => {
  const seen = []
  const fetcher = async (url, init) => {
    seen.push({ url: String(url), init })
    if (String(url).includes("/v1/claw/client-permission-validate")) {
      return new Response(permissionBody, { status: 200 })
    }
    return new Response("", { status: 404 })
  }
  const info = await x.fetchModelInfo(
    { access_key_id: "AK", secret_access_key: "SK", security_token: "ST", project_id: "P" },
    fetcher,
    {},
  )
  assert.equal(info.model_api_url_base, "https://maas-acct.example.com/")
  const h = new Headers(seen[0].init.headers)
  assert.match(h.get("authorization"), /^SDK-HMAC-SHA256 Access=AK,/)
  assert.equal(h.get("x-subscription-type"), "v2")
  assert.ok(h.get("x-security-token"))
  assert.ok(h.get("x-project-id"))
})

test("modelInfoChatConfig normalizes the base URL and builds Basic auth", () => {
  const cfg = x.modelInfoChatConfig({
    model_api_url_base: "https://maas-acct.example.com/",
    model_auth_info: { model_app_key: "K", model_app_secret: "S" },
  })
  assert.equal(cfg.baseUrl, "https://maas-acct.example.com/v2")
  assert.equal(cfg.authorization, `Basic ${Buffer.from("K:S").toString("base64")}`)
  assert.equal(x.modelInfoChatConfig({}), null)
})

test("extractModelInfo reads model_info from the payload or its subscription", () => {
  assert.equal(x.extractModelInfo({ model_info: { a: 1 } }).a, 1)
  assert.equal(x.extractModelInfo({ data: { model_info: { a: 1 } } }).a, 1)
  assert.equal(x.extractModelInfo({ data: { subscription: { model_info: { b: 2 } } } }).b, 2)
  assert.equal(x.extractModelInfo({}), null)
})

test("loader falls back to the account model_info when the studio list carries no auth", async () => {
  const cred = await makeCred()
  const seen = []
  const fetcher = async (url, init) => {
    const u = String(url)
    seen.push({ url: u, init })
    if (u.includes("/v1/studio/model-services")) return new Response(bareStudioBody, { status: 200 })
    if (u.includes("/v1/claw/client-permission-validate")) return new Response(permissionBody, { status: 200 })
    if (u.includes("/chat/completions")) return new Response(JSON.stringify({ choices: [] }), { status: 200 })
    return new Response("", { status: 404 })
  }
  const plugin = await OfficeAceAuthPlugin({ client: {} }, { fetch: fetcher })
  const loaded = await plugin.auth.loader(async () => makeAuth(cred))

  await loaded.fetch("https://agentarts.example.com/v2/chat/completions", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ model: "glm-5.2", messages: [] }),
  })

  const chatCall = seen.find((s) => s.url.includes("/chat/completions"))
  assert.ok(chatCall, "a chat request was made")
  assert.equal(chatCall.url, "https://maas-acct.example.com/v2/chat/completions")
  assert.match(new Headers(chatCall.init.headers).get("authorization"), /^Basic /)
})

test("provider.models applies the account model_info base URL", async () => {
  const cred = await makeCred()
  const fetcher = async (url) => {
    const u = String(url)
    if (u.includes("/v1/studio/model-services")) return new Response(bareStudioBody, { status: 200 })
    if (u.includes("/v1/claw/client-permission-validate")) return new Response(permissionBody, { status: 200 })
    return new Response("", { status: 404 })
  }
  const plugin = await OfficeAceAuthPlugin({ client: {} }, { fetch: fetcher })
  const models = await plugin.provider.models({ models: { "glm-5.2": {} } }, { auth: makeAuth(cred) })
  assert.equal(models["glm-5.2"].api, "https://maas-acct.example.com/v2")
})

test("loader returns nothing when not signed in", async () => {
  const plugin = await OfficeAceAuthPlugin({ client: {} }, {})
  assert.deepEqual(await plugin.auth.loader(async () => ({ type: "api", key: "k" })), {})
})

test("auth.refresh exchanges the refresh token for fresh credentials", async () => {
  const cred = await makeCred()
  const fetcher = async (url, init) => {
    assert.equal(String(url), x.tokenEndpoint({}))
    assert.equal(init.method, "POST")
    assert.ok(new Headers(init.headers).get("dpop"))
    return new Response(JSON.stringify({
      credentials: { access_key_id: "AK2", secret_access_key: "SK2", security_token: "ST2", expiration: "2031-01-01T00:00:00Z" },
      refresh_token: "R2",
    }), { status: 200 })
  }
  const plugin = await OfficeAceAuthPlugin({ client: {} }, { fetch: fetcher })
  const next = await plugin.auth.refresh(makeAuth(cred))
  const parsed = JSON.parse(next.access)
  assert.equal(parsed.access_key_id, "AK2")
  assert.equal(next.refresh, "R2")
  assert.equal(next.expires, Date.parse("2031-01-01T00:00:00Z"))
})

test("auth.usage reports the plan's credit window", async () => {
  const cred = await makeCred()
  const fetcher = async (url) => {
    if (String(url).includes("/v3.0/OS-CREDENTIAL/securitytokens")) return new Response("{}", { status: 404 })
    assert.ok(String(url).endsWith("/v1/subscription"))
    return new Response(JSON.stringify({ total_credits: 1000, used_credits: 400, plan_name: "企业版" }), { status: 200 })
  }
  const plugin = await OfficeAceAuthPlugin({ client: {} }, { fetch: fetcher, env: NO_ROUTING_ENV })
  const usage = await plugin.auth.usage(async () => makeAuth(cred))
  assert.equal(usage.plan, "企业版")
  assert.deepEqual(usage.windows, [{ name: "积分", used: 40, display: "400 / 1000", amount: 400, limit: 1000, unit: "credits" }])
})

// ---- OAuth state + code polling --------------------------------------------

test("requestState POSTs the state endpoint and returns the state", async () => {
  const fetcher = async (url, init) => {
    assert.equal(String(url), x.stateEndpoint({}))
    assert.equal(init.method, "POST")
    return new Response(JSON.stringify({ state: "S123" }), { status: 200 })
  }
  const state = await x.requestState(x.stateEndpoint({}), fetcher)
  assert.equal(state, "S123")
})

test("pollForCode polls until the cloud returns a code", async () => {
  let calls = 0
  const fetcher = async () => {
    calls += 1
    if (calls < 3) return new Response("{}", { status: 202 })
    return new Response(JSON.stringify({ code: "AUTHCODE" }), { status: 200 })
  }
  const code = await x.pollForCode("https://example.com/code?state=S", fetcher, { interval: 1, timeout: 5_000 })
  assert.equal(code, "AUTHCODE")
  assert.ok(calls >= 3)
})

test("pollForCode times out when no code ever arrives", async () => {
  const fetcher = async () => new Response("{}", { status: 202 })
  await assert.rejects(
    x.pollForCode("https://example.com/code?state=S", fetcher, { interval: 1, timeout: 50 }),
    /timed out/,
  )
})

// ---- OAuth flow (authorize + callback) -------------------------------------

test("startOAuthFlow returns a login URL and exchanges a polled code for a credential", async () => {
  const fetcher = async (url, init) => {
    const u = String(url)
    if (u.endsWith("/v1/claw/auth/state") && init.method === "POST") {
      return new Response(JSON.stringify({ state: "S" }), { status: 200 })
    }
    if (u.includes("/v1/claw/auth/code")) {
      return new Response(JSON.stringify({ code: "C" }), { status: 200 })
    }
    if (u.endsWith("/v1/oauth2/tokens")) {
      return new Response(JSON.stringify({
        credentials: { access_key_id: "AK", secret_access_key: "SK", security_token: "ST", expiration: "2030-01-01T00:00:00Z" },
        refresh_token: "R",
      }), { status: 200 })
    }
    return new Response("", { status: 404 })
  }

  const flow = await x.startOAuthFlow({}, fetcher)
  const url = new URL(flow.loginUrl)
  assert.equal(url.origin + url.pathname, "https://auth.huaweicloud.com/authui/v1/oauth2/authorize")
  assert.equal(url.searchParams.get("client_id"), x.DEFAULT_CLIENT_ID)
  assert.equal(url.searchParams.get("state"), "S")

  const outcome = await flow.result
  const cred = JSON.parse(outcome.access)
  assert.equal(cred.access_key_id, "AK")
  assert.equal(cred.refresh_token, "R")
})

test("auth.methods[0].authorize returns a url and a callback that resolves success", async () => {
  const fetcher = async (url, init) => {
    const u = String(url)
    if (u.endsWith("/v1/claw/auth/state") && init.method === "POST") return new Response(JSON.stringify({ state: "S" }), { status: 200 })
    if (u.includes("/v1/claw/auth/code")) return new Response(JSON.stringify({ code: "C" }), { status: 200 })
    if (u.endsWith("/v1/oauth2/tokens")) return new Response(JSON.stringify({
      credentials: { access_key_id: "AK", secret_access_key: "SK", security_token: "ST", expiration: "2030-01-01T00:00:00Z" },
      refresh_token: "R",
    }), { status: 200 })
    return new Response("", { status: 404 })
  }
  const plugin = await OfficeAceAuthPlugin({ client: {} }, { fetch: fetcher })
  const method = plugin.auth.methods[0]
  const { url, callback } = await method.authorize()
  assert.ok(url.startsWith("https://auth.huaweicloud.com/authui/v1/oauth2/authorize?"))
  const result = await callback()
  assert.equal(result.type, "success")
  const cred = JSON.parse(result.access)
  assert.equal(cred.access_key_id, "AK")
  assert.equal(result.refresh, "R")
})

// ---- local desktop routing ------------------------------------------------

async function withRoutingFixture(run) {
  const dir = await mkdtemp(join(tmpdir(), "officeace-routing-"))
  try {
    const userDir = join(dir, "routing_state", "users", "u1")
    await mkdir(userDir, { recursive: true })
    await writeFile(join(userDir, "models.json"), JSON.stringify({
      defaults: [
        {
          model_client_config: {
            model_name: "glm-5.2",
            api_base: "https://modelgw-0004.officeace.cn-southwest-2.huaweicloud-agentarts.com",
            api_key: "huawei-maas-session",
            custom_headers: { Authorization: "Basic MTIzNDU2Nzg5MGFiY2RlZg==" },
          },
        },
        {
          model_client_config: {
            model_name: "deepseek-v4.1-flash",
            api_base: "https://modelgw-0004.officeace.cn-southwest-2.huaweicloud-agentarts.com",
            custom_headers: { Authorization: "Basic MTIzNDU2Nzg5MGFiY2RlZg==" },
          },
        },
      ],
    }))
    const env = {
      OFFICEACE_ROUTING_DIR: dir,
      HUAWEI_CLAW_URL: "https://agentarts.example.com",
    }
    return await run(env, dir)
  } finally {
    await rm(dir, { recursive: true, force: true })
  }
}

test("localChatConfig reads the desktop app's per-user routing state", async () => {
  await withRoutingFixture(async (env, dir) => {
    const hit = await x.localChatConfig("glm-5.2", env)
    assert.ok(hit, "a chat config was resolved")
    assert.equal(hit.baseUrl, "https://modelgw-0004.officeace.cn-southwest-2.huaweicloud-agentarts.com/v2")
    assert.match(hit.authorization, /^Basic /)

    // An unlisted model falls back to the account-wide default entry.
    const fallback = await x.localChatConfig("no-such-model", env)
    assert.equal(fallback.baseUrl, hit.baseUrl)

    // An override pointing at a directory without routing state resolves to null.
    assert.equal(await x.localChatConfig("glm-5.2", { OFFICEACE_ROUTING_DIR: join(dir, "missing") }), null)
  })
})

test("loader routes chat to the local model gateway when the account has no model_info", async () => {
  await withRoutingFixture(async (env) => {
    const seen = []
    const fetcher = async (url, init) => {
      const u = String(url)
      seen.push({ url: u, init })
      if (u.includes("/v3.0/OS-CREDENTIAL/securitytokens")) return new Response("{}", { status: 404 })
      // No studio list and no subscription model_info for this account.
      if (u.includes("/v1/claw/client-permission-validate")) {
        return new Response(JSON.stringify({ account_id: "a", principal_urn: "p", principal_id: "i", subscription: null }), { status: 200 })
      }
      if (u.includes("/v1/studio/model-services")) return new Response(JSON.stringify({ data: [], total: 0 }), { status: 200 })
      if (u.includes("/chat/completions")) return new Response(JSON.stringify({ choices: [] }), { status: 200 })
      return new Response("", { status: 404 })
    }
    const plugin = await OfficeAceAuthPlugin({ client: {} }, { fetch: fetcher, env })
    const cred = await makeCred()
    const loaded = await plugin.auth.loader(async () => makeAuth(cred))

    await loaded.fetch("https://agentarts.example.com/v2/chat/completions", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ model: "glm-5.2", messages: [] }),
    })

    const chatCall = seen.find((s) => s.url.includes("/chat/completions"))
    assert.ok(chatCall, "a chat request was made")
    assert.equal(
      chatCall.url,
      "https://modelgw-0004.officeace.cn-southwest-2.huaweicloud-agentarts.com/v2/chat/completions",
    )
    assert.equal(new Headers(chatCall.init.headers).get("authorization"), "Basic MTIzNDU2Nzg5MGFiY2RlZg==")
  })
})
