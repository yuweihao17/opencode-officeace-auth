// OfficeAce (华为云果办 / OfficeClaw) as a magpie / OpenCode provider plugin.
//
// OfficeAce, Huawei Cloud's office-productivity agent (果办), serves its models
// over an OpenAI-compatible Chat Completions API. Unlike a plain OpenAI
// provider it does NOT take a static API key: requests are authenticated either
// by MaaS Basic auth (per-model app_key/app_secret) or by Huawei SDK-HMAC-SHA256
// signed temporary AK/SK/security-token credentials, and those credentials are
// obtained by signing in to Huawei Cloud with OAuth (PKCE + DPoP).
//
// This plugin mirrors the real OfficeAce desktop agent (and the shipped CodeArts
// plugin this is modelled on):
//
//   1. `auth.methods[0]` is `{ type: "oauth" }`. `authorize()` asks the cloud for
//      an OAuth `state` (POST /v1/claw/auth/state), builds the Huawei Cloud
//      portal authorize URL (PKCE S256 + DPoP ES256) and returns it for magpie
//      to open. `callback()` then polls /v1/claw/auth/code?state= until the
//      browser sign-in completes and a code arrives, and exchanges it at the STS
//      token endpoint for rotating AK/SK/security-token credentials.
//   2. The sign-in is PKCE: a random code_verifier is sent to the STS token
//      endpoint with the code and the S256 challenge's pre-image. It is also a
//      DPoP flow: a fresh ES256 (P-256) key pair signs each token request, and
//      the private key JWK is persisted so refresh requests can sign with it too.
//   3. STS answers with rotating IAMv5 AK/SK/security-token credentials plus a
//      refresh_token. For endpoints that require IAMv3 (the studio model list),
//      the v5 credential is exchanged for a v3 credential via
//      /v3.0/OS-CREDENTIAL/securitytokens. The whole credential (verifier + DPoP
//      key) is stored as JSON in the account's `access` field.
//   4. `auth.refresh` silently renews before expiry via `grant_type =
//      refresh_token`; the same verifier and DPoP key are reused.
//   5. The account's live model list is read from signed GETs to
//      /v1/studio/model-services; subscription/usage from /v1/subscription.
//   6. Chat requests use MaaS Basic auth (from the model's model_auth_info) when
//      available, or SDK-HMAC-SHA256 signing as a fallback.
//
// See README.md / DESIGN.md.

const PROVIDER = "officeace"
const NPM = "@ai-sdk/openai-compatible" // chat completions

// ---- endpoints & flow constants --------------------------------------------
//
// All base URLs are env-overridable, mirroring the green-package defaults.

const DEFAULT_CLAW_BASE = "https://agentarts.cn-southwest-2.myhuaweicloud.com"
const DEFAULT_AUTH_BASE = "https://auth.huaweicloud.com"
const DEFAULT_IAM_BASE = "https://sts.cn-north-4.myhuaweicloud.com"
const DEFAULT_IAM_KEYSTONE_BASE = "https://iam.myhuaweicloud.com"
const DEFAULT_CLIENT_ID = "pdp5_for_agentarts"
const REGION_ID = "cn-southwest-2"
const IAM_V3_DURATION_SECONDS = 24 * 60 * 60

const GRANT_AUTHORIZATION_CODE = "authorization_code"
const GRANT_REFRESH_TOKEN = "refresh_token"

const TOKEN_TIMEOUT_MS = 60_000
const REQUEST_TIMEOUT_MS = 30_000
const CODE_POLL_INTERVAL_MS = 1_500
const CODE_POLL_TIMEOUT_MS = 300_000
const REFRESH_LEAD_MS = 30 * 60 * 1000

const MODEL_PAGE_SIZE = 500
const MODEL_MAX_PAGES = 20
const MODEL_PROVIDER_ID = 100

// Renew the IAMv3 credential this long before it expires.
const V3_REFRESH_LEAD_MS = 10 * 60 * 1000

// A minimal catalog shown before (or instead of) the account's live list. The
// live list from /v1/studio/model-services is authoritative; these are
// placeholders so a cold start still offers something.
const CATALOG = [
  { id: "glm-4.6", name: "GLM-4.6" },
  { id: "deepseek-v3.1", name: "DeepSeek V3.1" },
]

// ---- env / url resolution ---------------------------------------------------

const stripTrailingSlash = (s) => (typeof s === "string" ? s.replace(/\/+$/, "") : "")

function firstEnv(env, ...keys) {
  for (const k of keys) {
    const v = env?.[k]
    if (typeof v === "string" && v.trim()) return v.trim()
  }
  return undefined
}

const clawBase = (env) =>
  stripTrailingSlash(firstEnv(env, "HUAWEI_CLAW_URL", "OFFICE_CLAW_API_HOST") ?? DEFAULT_CLAW_BASE)
const authBaseUrl = (env) => stripTrailingSlash(firstEnv(env, "OAUTH_AUTH_BASE") ?? DEFAULT_AUTH_BASE)
const iamTokenBase = (env) => stripTrailingSlash(firstEnv(env, "OAUTH_IAM_BASE_URL") ?? DEFAULT_IAM_BASE)
const iamKeystoneBase = (env) => stripTrailingSlash(firstEnv(env, "IAM_URL") ?? DEFAULT_IAM_KEYSTONE_BASE)
const iamSecurityTokenUrl = (env) =>
  firstEnv(env, "OFFICE_CLAW_IAM_SECURITY_TOKEN_URL", "OFFICE_CLAW_CAS_IAM_SECURITY_TOKEN_URL") ??
  `${iamKeystoneBase(env)}/v3.0/OS-CREDENTIAL/securitytokens`

const redirectUri = (env) => `${clawBase(env)}/v1/claw/auth/callback`
const tokenEndpoint = (env) => `${iamTokenBase(env)}/v1/oauth2/tokens`
const stateEndpoint = (env) => `${clawBase(env)}/v1/claw/auth/state`
const codePollUrl = (env, state) => `${clawBase(env)}/v1/claw/auth/code?state=${encodeURIComponent(state)}`
const modelServicesUrl = (env, page, size) =>
  `${clawBase(env)}/v1/studio/model-services?provider_id=${MODEL_PROVIDER_ID}&page_num=${page}&page_size=${size}`
const subscribeUrl = (env) => `${clawBase(env)}/v1/studio/maas-model-services/subscribe`
const subscriptionUrl = (env) => `${clawBase(env)}/v1/subscription`
const subscriptionUsageUrl = (env) => `${clawBase(env)}/v1/subscription/usage`
const permissionValidateUrl = (env) => `${clawBase(env)}/v1/claw/client-permission-validate`

// ---- small helpers ---------------------------------------------------------

const firstOf = (...vs) => vs.find((v) => typeof v === "string" && v.trim())?.trim() ?? ""

const asRecord = (v) => (typeof v === "object" && v !== null && !Array.isArray(v) ? v : {})

function safeJson(text) {
  try {
    const parsed = JSON.parse(text)
    return typeof parsed === "object" && parsed !== null ? parsed : null
  } catch {
    return null
  }
}

function num(v) {
  if (typeof v === "number" && Number.isFinite(v)) return v
  if (typeof v === "string" && v.trim()) {
    const n = Number(v)
    if (Number.isFinite(n)) return n
  }
  return 0
}

const clamp = (n) => Math.max(0, Math.min(100, n))

function prettify(id) {
  return String(id)
    .split(/[-_]/)
    .filter(Boolean)
    .map((w) => w.charAt(0).toUpperCase() + w.slice(1))
    .join(" ")
}

/** Normalize a MaaS chat base URL: trim, ensure scheme, ensure trailing /v2. */
function normalizeMaasBaseUrl(rawBaseUrl) {
  const trimmed = String(rawBaseUrl).trim().replace(/\/+$/, "")
  const withScheme = /^https?:\/\//i.test(trimmed) ? trimmed : `https://${trimmed}`
  return withScheme.endsWith("/v2") ? withScheme : `${withScheme}/v2`
}

// ---- WebCrypto primitives --------------------------------------------------

function subtle() {
  const c = globalThis.crypto
  if (!c?.subtle) throw new Error("OfficeAce: WebCrypto (globalThis.crypto.subtle) is unavailable")
  return c.subtle
}

const typed = (u8) => (u8 instanceof Uint8Array ? u8 : new Uint8Array(u8))

function randomBytes(n) {
  const out = new Uint8Array(n)
  globalThis.crypto.getRandomValues(out)
  return out
}

const hex = (u8) => Array.from(u8).map((b) => b.toString(16).padStart(2, "0")).join("")

function randomHex(n) {
  return hex(randomBytes(n))
}

function b64url(u8) {
  let s = ""
  for (const b of u8) s += String.fromCharCode(b)
  return btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "")
}

const utf8 = (s) => new TextEncoder().encode(s)

async function sha256Hex(data) {
  const digest = await subtle().digest("SHA-256", typed(data))
  return hex(new Uint8Array(digest))
}

async function hmacSha256Hex(key, data) {
  const cryptoKey = await subtle().importKey(
    "raw", typed(key), { name: "HMAC", hash: "SHA-256" }, false, ["sign"],
  )
  const sig = await subtle().sign("HMAC", cryptoKey, typed(data))
  return hex(new Uint8Array(sig))
}

/** PKCE pair: a random 48-byte base64url verifier + its S256 challenge. */
async function generatePkcePair() {
  const codeVerifier = b64url(randomBytes(48))
  const digest = await subtle().digest("SHA-256", utf8(codeVerifier))
  return { codeVerifier, codeChallenge: b64url(new Uint8Array(digest)) }
}

/** Generate an ES256 (P-256) DPoP key pair as JWKs. */
async function generateDpopKeyPair() {
  const pair = await subtle().generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, ["sign", "verify"])
  const jwk = await subtle().exportKey("jwk", pair.privateKey)
  return {
    privateKeyJwk: { kty: "EC", crv: "P-256", x: jwk.x, y: jwk.y, d: jwk.d },
    publicKeyJwk: { kty: "EC", crv: "P-256", x: jwk.x, y: jwk.y },
  }
}

/** Recover a DPoP key pair from a persisted private JWK. */
function keyPairFromStoredJwk(jwk) {
  return {
    privateKeyJwk: { kty: "EC", crv: "P-256", x: jwk.x, y: jwk.y, d: jwk.d },
    publicKeyJwk: { kty: "EC", crv: "P-256", x: jwk.x, y: jwk.y },
  }
}

/** Sign a `dpop+jwt` proof (htm=method, htu=URL) with the DPoP private key. */
async function signDpopJws(keyPair, htm, htu) {
  const header = { alg: "ES256", typ: "dpop+jwt", jwk: keyPair.publicKeyJwk }
  const payload = { htm, htu, iat: Math.floor(Date.now() / 1000), jti: randomHex(32) }
  const signingInput = `${b64url(utf8(JSON.stringify(header)))}.${b64url(utf8(JSON.stringify(payload)))}`
  const key = await subtle().importKey(
    "jwk", keyPair.privateKeyJwk, { name: "ECDSA", namedCurve: "P-256" }, false, ["sign"],
  )
  const sig = await subtle().sign({ name: "ECDSA", hash: "SHA-256" }, key, utf8(signingInput))
  // WebCrypto ECDSA returns raw r||s, which is exactly the JWS ES256 format.
  return `${signingInput}.${b64url(new Uint8Array(sig))}`
}

// ---- Huawei request signing (ported from the OfficeAce dist) ---------------
//
// Two algorithms are supported, exactly as the dist's ua-signed-request module:
//   - SDK-HMAC-SHA256  : stringToSign = "SDK-HMAC-SHA256\n{date}\n{sha256(canonical)}"
//   - V11-HMAC-SHA256  : derives a signing key from (sk, date8, scope) first.
// The canonical request is identical for both: METHOD\nURI\nQUERY\nHEADERS\n\nSIGNED_HEADERS\nPAYLOAD_HASH
// with RFC-3986 encoded path segments and a sorted, encoded query string.

const ALGO_SDK = "SDK-HMAC-SHA256"
const ALGO_V11 = "V11-HMAC-SHA256"
const V11_SERVICE = "apic"
const UNSIGNED_PAYLOAD = "UNSIGNED-PAYLOAD"
const CONTENT_SHA256_HEADER = "x-sdk-content-sha256"

/** ISO-8601 date stamp with separators removed: 20260101T000000Z */
function sdkDate(date = new Date()) {
  return date.toISOString().replace(/[:-]|\.\d{3}/g, "")
}

/** RFC 3986 URI-encode a segment, upper-casing the percent-hex digits. */
function rfc3986Encode(s) {
  return encodeURIComponent(s).replace(/[!'()*]/g, (c) => `%${c.charCodeAt(0).toString(16).toUpperCase()}`)
}

/** Canonical URI: each path segment decoded then RFC-3986 encoded, trailing /. */
function canonicalUri(url) {
  const r = (url.pathname || "/")
    .split("/")
    .map((n) => rfc3986Encode(decodeURIComponent(n)))
    .join("/")
  if (!r.endsWith("/")) return `${r}/`
  return r
}

/** Canonical query string: sorted by (key, value), RFC-3986 encoded. */
function canonicalQuery(url) {
  const pairs = []
  url.searchParams.forEach((value, key) => pairs.push([key, value]))
  pairs.sort(([a], [b]) => a.localeCompare(b))
  return pairs.map(([k, v]) => `${rfc3986Encode(k)}=${rfc3986Encode(v)}`).join("&")
}

/** Lowercase, trimmed, single-spaced header map. */
function lowerHeaders(headers) {
  const out = {}
  for (const [k, v] of Object.entries(headers)) out[k.toLowerCase()] = String(v).trim().replace(/\s+/g, " ")
  return out
}

function buildCanonicalRequest(method, url, headers, signedHeaderKeys, payloadHash) {
  const headerLines = signedHeaderKeys.map((k) => `${k}:${headers[k] ?? ""}`).join("\n")
  return [
    method.toUpperCase(),
    canonicalUri(url),
    canonicalQuery(url),
    headerLines,
    "",
    signedHeaderKeys.join(";"),
    payloadHash,
  ].join("\n")
}

/** SDK-HMAC-SHA256 Authorization header value. */
async function sdkAuthorization(method, url, headers, body, accessKey, secretKey, preSigned = false) {
  const keys = preSigned
    ? [CONTENT_SHA256_HEADER, "x-sdk-date"].sort()
    : Object.keys(headers).sort()
  const payloadHash = preSigned ? UNSIGNED_PAYLOAD : await sha256Hex(body)
  const canonical = buildCanonicalRequest(method, url, headers, keys, payloadHash)
  const stringToSign = [ALGO_SDK, headers["x-sdk-date"], await sha256Hex(utf8(canonical))].join("\n")
  const signature = await hmacSha256Hex(utf8(secretKey), utf8(stringToSign))
  return `${ALGO_SDK} Access=${accessKey}, SignedHeaders=${keys.join(";")}, Signature=${signature}`
}

/** V11-HMAC-SHA256 signing-key derivation: HMAC(HMAC(sk, date8), scope + 0x01)[:32]. */
async function v11SigningKey(secretKey, date8, scope) {
  const kDate = await hmacSha256Hex(utf8(secretKey), utf8(date8))
  const buf = Buffer.concat([Buffer.from(scope, "utf8"), Buffer.from([1])])
  // hmacSha256Hex returns hex; re-import as bytes for the second HMAC.
  const kDateBytes = typed(Buffer.from(kDate, "hex"))
  return await hmacSha256Hex(kDateBytes, buf)
}

/** V11-HMAC-SHA256 Authorization header value. */
async function v11Authorization(method, url, headers, body, accessKey, secretKey, regionId, preSigned = false) {
  const keys = preSigned
    ? [CONTENT_SHA256_HEADER, "x-sdk-date"].sort()
    : Object.keys(headers).sort()
  const payloadHash = preSigned ? UNSIGNED_PAYLOAD : await sha256Hex(body)
  const canonical = buildCanonicalRequest(method, url, headers, keys, payloadHash)
  const date = headers["x-sdk-date"]
  const scope = `${date.substring(0, 8)}/${regionId}/${V11_SERVICE}`
  const stringToSign = [ALGO_V11, date, scope, await sha256Hex(utf8(canonical))].join("\n")
  const signingKey = await v11SigningKey(secretKey, date.substring(0, 8), scope)
  const signature = await hmacSha256Hex(typed(Buffer.from(signingKey, "hex")), utf8(stringToSign))
  return `${ALGO_V11} Credential=${accessKey}/${scope}, SignedHeaders=${keys.join(";")}, Signature=${signature}`
}

function setHeader(headers, name, value) {
  for (const k of Object.keys(headers)) if (k !== name && k.toLowerCase() === name.toLowerCase()) delete headers[k]
  headers[name] = value
}

/**
 * Build the signed header map for a Huawei request.
 * `algorithm` selects SDK-HMAC-SHA256 (default) or V11-HMAC-SHA256 (needs regionId).
 * Returns a plain object of header name → value (including Authorization).
 */
async function buildSignedHeaders({
  method, url, credential, bodyText = "", headers = {}, contentType, algorithm = ALGO_SDK,
  regionId = "", preSigned = false, dateOverride,
}) {
  const ak = credential.accessKey?.trim() || ""
  const sk = credential.secretKey?.trim() || ""
  const st = credential.securityToken?.trim() || ""
  const projectId = credential.projectId?.trim() || ""
  if (!ak || !sk || !st) return null
  if (algorithm === ALGO_V11 && !regionId.trim()) return null

  const out = { ...headers }
  setHeader(out, "X-Sdk-Date", sdkDate(dateOverride))
  setHeader(out, "X-Security-Token", st)
  setHeader(out, "Host", headers.host ?? headers.Host ?? new URL(url).host)
  if (contentType) setHeader(out, "Content-Type", contentType)
  if (projectId) setHeader(out, "X-Project-ID", projectId)
  if (preSigned) setHeader(out, "X-Sdk-Content-Sha256", UNSIGNED_PAYLOAD)

  const lowered = lowerHeaders(out)
  const auth = algorithm === ALGO_V11
    ? await v11Authorization(method, new URL(url), lowered, bodyText, ak, sk, regionId, preSigned)
    : await sdkAuthorization(method, new URL(url), lowered, bodyText, ak, sk, preSigned)
  setHeader(out, "Authorization", auth)
  return out
}

// ---- IAM v3 security-token exchange ----------------------------------------
//
// The OAuth token endpoint issues IAMv5 credentials. Some endpoints (the studio
// model list) require IAMv3, obtained by POSTing to /v3.0/OS-CREDENTIAL/securitytokens
// with the v5 credential signing the request.

/** Unwrap a `{data: ...}` or `{result: ...}` envelope, else return as-is. */
function unwrapPayload(value) {
  if (!asRecord(value)) return null
  if (asRecord(value.data)) return value.data
  if (asRecord(value.result)) return value.result
  return value
}

const readStringField = (record, ...keys) => {
  for (const k of keys) {
    const v = record?.[k]
    if (typeof v === "string" && v.trim()) return v.trim()
  }
  return ""
}

/**
 * Exchange an IAMv5 credential for an IAMv3 credential. Best-effort: returns
 * null on any failure so callers can fall back to v5.
 */
async function exchangeIamV3SecurityToken({ v5Credential, iamSecurityTokenUrl: tokenUrl, fetchImpl = fetch, env }) {
  if (!v5Credential.accessKey || !v5Credential.secretKey || !v5Credential.securityToken) return null
  const body = JSON.stringify({
    auth: { identity: { methods: ["token"], token: { duration_seconds: IAM_V3_DURATION_SECONDS } } },
  })
  const signed = await buildSignedHeaders({
    method: "POST", url: tokenUrl,
    credential: { accessKey: v5Credential.accessKey, secretKey: v5Credential.secretKey, securityToken: v5Credential.securityToken, projectId: "" },
    bodyText: body, contentType: "application/json;charset=utf8", algorithm: ALGO_SDK,
  })
  if (!signed) return null
  let response
  try {
    response = await fetchImpl(tokenUrl, { method: "POST", headers: signed, body, signal: AbortSignal.timeout(REQUEST_TIMEOUT_MS) })
  } catch {
    return null
  }
  if (!response.ok) return null
  const payload = unwrapPayload(await response.json().catch(() => null))
  const cred = payload && typeof payload.credential === "object" ? payload.credential : null
  const access = readStringField(cred, "access")
  const secret = readStringField(cred, "secret")
  const securityToken = readStringField(cred, "securitytoken", "security_token", "securityToken")
  const expiresAt = readStringField(cred, "expires_at", "expiresAt")
  if (!access || !secret || !securityToken) return null
  return { accessKey: access, secretKey: secret, securityToken, expiresAt }
}

/**
 * Resolve a v3 credential: use the provided one if still valid, else exchange
 * v5 → v3. Returns null if neither is available.
 */
async function resolveV3Credential(v5, v3, options) {
  if (v3?.accessKey && v3.securityToken && !v3Expired(v3)) {
    return { accessKey: v3.accessKey, secretKey: v3.secretKey, securityToken: v3.securityToken, projectId: v5.projectId || v3.projectId || "" }
  }
  const fresh = await exchangeIamV3SecurityToken({ v5Credential: v5, ...options })
  if (!fresh) return null
  return { accessKey: fresh.accessKey, secretKey: fresh.secretKey, securityToken: fresh.securityToken, projectId: v5.projectId || "" }
}

function v3Expired(v3) {
  if (!v3?.expiresAt) return false
  const parsed = Date.parse(v3.expiresAt)
  if (Number.isNaN(parsed)) return false
  return parsed - Date.now() <= V3_REFRESH_LEAD_MS
}

/**
 * Send a signed request, preferring the v3 credential when `preferV3`, and
 * falling back from v5 → v3 on an APIG.0301 rejection. Mirrors the dist's
 * fetchHuaweiSignedWithIamV3Fallback.
 */
async function fetchSigned({
  method, url, bodyText, contentType, v5Credential, v3Credential, fetchImpl = fetch,
  algorithm = ALGO_SDK, regionId = "", headers, preferV3 = false, iamSecurityTokenUrl: tokenUrl, env,
}) {
  const body = bodyText ?? ""
  const merge = (signed) => (headers ? { ...signed, ...headers } : signed)

  if (preferV3) {
    const v3 = await resolveV3Credential(v5Credential, v3Credential, { iamSecurityTokenUrl: tokenUrl, fetchImpl, env })
    if (v3) {
      const signed = await buildSignedHeaders({ method, url, credential: v3, bodyText: body, contentType, algorithm, regionId })
      if (signed) return fetchImpl(url, { method, headers: merge(signed), body, signal: AbortSignal.timeout(REQUEST_TIMEOUT_MS) })
    }
    const signed = await buildSignedHeaders({ method, url, credential: v5Credential, bodyText: body, contentType, algorithm, regionId })
    if (!signed) throw new Error("credentials_required")
    return fetchImpl(url, { method, headers: merge(signed), body, signal: AbortSignal.timeout(REQUEST_TIMEOUT_MS) })
  }

  const signed = await buildSignedHeaders({ method, url, credential: v5Credential, bodyText: body, contentType, algorithm, regionId })
  if (!signed) throw new Error("credentials_required")
  let res = await fetchImpl(url, { method, headers: merge(signed), body, signal: AbortSignal.timeout(REQUEST_TIMEOUT_MS) })
  if (res.status !== 401) return res
  const errBody = await res.clone().json().catch(() => null)
  if (readStringField(errBody, "error_code") !== "APIG.0301") return res
  const v3 = await resolveV3Credential(v5Credential, v3Credential, { iamSecurityTokenUrl: tokenUrl, fetchImpl, env })
  if (!v3) return res
  const retry = await buildSignedHeaders({ method, url, credential: v3, bodyText: body, contentType, algorithm, regionId })
  if (!retry) return res
  return fetchImpl(url, { method, headers: merge(retry), body, signal: AbortSignal.timeout(REQUEST_TIMEOUT_MS) })
}

// ---- OAuth token exchange --------------------------------------------------

/** Normalize an STS token response into a persisted OfficeAce credential. */
function credentialFromTokenResponse(token, codeVerifier, keyPair) {
  const c = token?.credentials ?? {}
  return {
    access_key_id: c.access_key_id ?? "",
    secret_access_key: c.secret_access_key ?? "",
    security_token: c.security_token ?? "",
    project_id: c.project_id ?? "",
    expires_at: c.expiration ?? "",
    refresh_token: token?.refresh_token,
    code_verifier: codeVerifier,
    dpop_private_key_jwk: keyPair.privateKeyJwk,
  }
}

/** The credential a sign-in carries; magpie keeps it in the `access` field. */
function credentialOf(auth) {
  if (!auth || auth.type !== "oauth") return null
  const raw = typeof auth.access === "string" ? auth.access : ""
  if (!raw) return null
  const cred = safeJson(raw)
  return cred && typeof cred.access_key_id === "string" && cred.access_key_id ? cred : null
}

function expiresFromCredential(cred) {
  if (cred?.expires_at) {
    const parsed = Date.parse(cred.expires_at)
    if (!Number.isNaN(parsed)) return parsed
  }
  return Date.now() + 86_400_000
}

/** POST the STS token endpoint with a DPoP proof. */
async function requestToken(body, keyPair, tokenUrl, fetcher) {
  const dpop = await signDpopJws(keyPair, "POST", tokenUrl)
  let response
  try {
    response = await fetcher(tokenUrl, {
      method: "POST",
      headers: { DPoP: dpop, "Content-Type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams(body).toString(),
      signal: AbortSignal.timeout(TOKEN_TIMEOUT_MS),
    })
  } catch (e) {
    throw new Error(`OfficeAce token request network error: ${String(e)}`)
  }
  let data = null
  try {
    data = await response.json()
  } catch {
    data = null
  }
  if (!response.ok || !data?.credentials) {
    const message = `OfficeAce token request failed: ${response.status}${data ? ` ${JSON.stringify(data)}` : ""}`
    const errorCode = String(data?.error_code ?? "")
    if (data?.error === "invalid_grant" || errorCode.includes("ExpiredRefreshToken")) {
      throw Object.assign(new Error(message), { signIn: "expired" })
    }
    throw new Error(message)
  }
  return data
}

function exchangeAuthorizationCode(code, codeVerifier, keyPair, redirect, tokenUrl, fetcher) {
  return requestToken({
    client_id: DEFAULT_CLIENT_ID,
    code,
    code_verifier: codeVerifier,
    grant_type: GRANT_AUTHORIZATION_CODE,
    redirect_uri: redirect,
  }, keyPair, tokenUrl, fetcher)
}

function exchangeRefreshToken(refreshToken, codeVerifier, keyPair, tokenUrl, fetcher) {
  return requestToken({
    client_id: DEFAULT_CLIENT_ID,
    code_verifier: codeVerifier,
    grant_type: GRANT_REFRESH_TOKEN,
    refresh_token: refreshToken,
  }, keyPair, tokenUrl, fetcher)
}

/** Refresh a stored credential, reusing its verifier + DPoP private key. */
async function refreshCredential(cred, tokenUrl, fetcher) {
  const refreshToken = firstOf(cred.refresh_token)
  if (!refreshToken || !cred.code_verifier || !cred.dpop_private_key_jwk) {
    throw new Error("OfficeAce: credential cannot be refreshed (missing refresh_token/code_verifier/dpop key)")
  }
  const keyPair = keyPairFromStoredJwk(cred.dpop_private_key_jwk)
  const token = await exchangeRefreshToken(refreshToken, cred.code_verifier, keyPair, tokenUrl, fetcher)
  const next = credentialFromTokenResponse(token, cred.code_verifier, keyPair)
  if (!next.refresh_token) next.refresh_token = refreshToken
  for (const k of ["project_id"]) {
    if (cred[k] && !next[k]) next[k] = cred[k]
  }
  return next
}

// ---- OAuth login: state + authorize URL + code polling ---------------------

/** POST /v1/claw/auth/state → {state}. The cloud generates the state. */
async function requestState(stateUrl, fetcher) {
  let response
  try {
    response = await fetcher(stateUrl, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      signal: AbortSignal.timeout(REQUEST_TIMEOUT_MS),
    })
  } catch (e) {
    throw new Error(`OfficeAce state request network error: ${String(e)}`)
  }
  if (!response.ok) throw new Error(`OfficeAce state request failed: ${response.status}`)
  const data = await response.json().catch(() => ({}))
  const state = typeof data?.state === "string" ? data.state.trim() : ""
  if (!state) throw new Error("OfficeAce: cloud did not return a state")
  return state
}

/** Build the Huawei Cloud portal authorize URL (PKCE + DPoP, mirrors the desktop). */
function buildOAuthLoginUrl(authBase, pkce, state, redirect) {
  const params = new URLSearchParams({
    client_id: DEFAULT_CLIENT_ID,
    code_challenge: pkce.codeChallenge,
    code_challenge_method: "SHA-256",
    state,
    scope: "openid",
    redirect_uri: redirect,
    response_type: "code",
  })
  return `${authBase}/authui/v1/oauth2/authorize?${params.toString()}`
}

/**
 * Poll /v1/claw/auth/code?state= until the cloud returns {code} (the browser
 * sign-in completed), or the timeout expires. Returns the authorization code.
 */
async function pollForCode(pollUrl, fetcher, { interval = CODE_POLL_INTERVAL_MS, timeout = CODE_POLL_TIMEOUT_MS } = {}) {
  const deadline = Date.now() + timeout
  for (;;) {
    if (Date.now() >= deadline) throw new Error("OfficeAce OAuth login timed out waiting for code")
    let response
    try {
      response = await fetcher(pollUrl, {
        method: "GET",
        headers: { Accept: "application/json" },
        signal: AbortSignal.timeout(REQUEST_TIMEOUT_MS),
      })
    } catch {
      await new Promise((r) => setTimeout(r, interval))
      continue
    }
    if (response.ok) {
      const data = await response.json().catch(() => ({}))
      const code = typeof data?.code === "string" ? data.code.trim() : ""
      if (code) return code
    }
    await new Promise((r) => setTimeout(r, interval))
  }
}

/**
 * Start an OAuth flow and return its login URL immediately (magpie opens it).
 * `result` resolves once the code is polled and exchanged for a credential.
 */
async function startOAuthFlow(env, fetcher) {
  const pkce = await generatePkcePair()
  const keyPair = await generateDpopKeyPair()
  const state = await requestState(stateEndpoint(env), fetcher)
  const redirect = redirectUri(env)
  const loginUrl = buildOAuthLoginUrl(authBaseUrl(env), pkce, state, redirect)

  const result = (async () => {
    const code = await pollForCode(codePollUrl(env, state), fetcher)
    const token = await exchangeAuthorizationCode(code, pkce.codeVerifier, keyPair, redirect, tokenEndpoint(env), fetcher)
    return {
      access: JSON.stringify(credentialFromTokenResponse(token, pkce.codeVerifier, keyPair)),
      expires: expiresFromCredential(credentialFromTokenResponse(token, pkce.codeVerifier, keyPair)),
    }
  })()

  // Settle in the background so an early failure never becomes an unhandled rejection.
  result.catch(() => {})

  return { loginUrl, result }
}

// ---- signed GET / POST helpers --------------------------------------------

/** Turn a request body (string / bytes / stream / blob) into bytes. */
async function toBytes(body) {
  if (body == null) return new Uint8Array()
  if (typeof body === "string") return utf8(body)
  if (body instanceof Uint8Array) return body
  if (body instanceof ArrayBuffer) return new Uint8Array(body)
  if (ArrayBuffer.isView(body)) return new Uint8Array(body.buffer, body.byteOffset, body.byteLength)
  if (typeof body?.getReader === "function") {
    const chunks = []
    const reader = body.getReader()
    for (;;) {
      const { done, value } = await reader.read()
      if (done) break
      chunks.push(typed(value))
    }
    const total = chunks.reduce((n, c) => n + c.length, 0)
    const out = new Uint8Array(total)
    let offset = 0
    for (const c of chunks) {
      out.set(c, offset)
      offset += c.length
    }
    return out
  }
  if (typeof body?.arrayBuffer === "function") return new Uint8Array(await body.arrayBuffer())
  return utf8(String(body))
}

/** A signed GET returning the response, or undefined on any failure. */
async function signedGet(url, cred, fetcher, { extraHeaders, preferV3 = false, v3Credential, env } = {}) {
  const v5 = { accessKey: cred.access_key_id, secretKey: cred.secret_access_key, securityToken: cred.security_token, projectId: cred.project_id || "" }
  try {
    const res = await fetchSigned({
      method: "GET", url, v5Credential: v5, v3Credential, fetchImpl: fetcher,
      algorithm: ALGO_SDK, preferV3, iamSecurityTokenUrl: iamSecurityTokenUrl(env), env,
      headers: extraHeaders,
    })
    if (!res.ok) return undefined
    return res
  } catch {
    return undefined
  }
}

// ---- model list ------------------------------------------------------------

/**
 * Normalize a studio model-services item, mirroring the desktop's cke():
 *   {model_name, service_name, api_url, logo, model_series, is_reasoning,
 *    context_length, is_subscribed, model_auth_info?, model_api_url_base?}
 * → {id, name, baseUrl?, icon?, modelSeries?, isReasoning?, contextLength?,
 *    isSubscribed?, authInfo?, apiBaseUrl?}
 */
function parseModelInfo(m) {
  const modelName = typeof m.model_name === "string" ? m.model_name.trim() : ""
  const serviceName = typeof m.service_name === "string" ? m.service_name.trim() : ""
  const id = modelName || serviceName
  if (!id) return undefined
  const out = { id, name: serviceName || modelName }

  const apiUrl = typeof m.api_url === "string" && m.api_url.trim() ? m.api_url.trim() : ""
  if (apiUrl) out.baseUrl = apiUrl

  const logo = typeof m.logo === "string" && m.logo.trim() ? m.logo.trim() : ""
  if (logo) out.icon = logo

  const series = typeof m.model_series === "string" && m.model_series.trim() ? m.model_series.trim() : ""
  if (series) out.modelSeries = series

  if (typeof m.is_reasoning === "boolean") out.isReasoning = m.is_reasoning

  const ctx = typeof m.context_length === "string" && m.context_length.trim() ? m.context_length.trim() : ""
  if (ctx) out.contextLength = ctx

  if (typeof m.is_subscribed === "boolean") out.isSubscribed = m.is_subscribed

  // MaaS chat auth material (present after subscribing to a model).
  if (asRecord(m.model_auth_info)) out.authInfo = m.model_auth_info
  const apiBase = typeof m.model_api_url_base === "string" && m.model_api_url_base.trim() ? m.model_api_url_base.trim() : ""
  if (apiBase) out.apiBaseUrl = apiBase

  return out
}

/**
 * Fetch the account's live model list from /v1/studio/model-services, paginated
 * and signed with the IAMv3 credential (preferred). Mirrors the desktop loop.
 */
async function fetchRemoteModels(cred, fetcher, env, v3Credential) {
  const models = []
  const seen = new Set()
  let total = null

  for (let page = 1; page <= MODEL_MAX_PAGES; page += 1) {
    const res = await signedGet(modelServicesUrl(env, page, MODEL_PAGE_SIZE), cred, fetcher, {
      preferV3: true, v3Credential, env,
    })
    if (!res) break
    const body = await res.json().catch(() => ({}))
    const items = Array.isArray(body.data) ? body.data.filter((v) => typeof v === "object" && v !== null) : []
    if (typeof body.total === "number") total = body.total
    for (const item of items) {
      const mi = parseModelInfo(item)
      if (!mi || seen.has(mi.id)) continue
      seen.add(mi.id)
      models.push(mi)
    }
    if (items.length === 0 || items.length < MODEL_PAGE_SIZE || (total !== null && models.length >= total)) break
  }

  return models
}

// ---- MaaS chat auth --------------------------------------------------------

/** Build the MaaS Basic auth header from a model's model_auth_info. */
function buildMaasAuthorization(authInfo) {
  const appKey = authInfo?.model_app_key?.trim()
  const appSecret = authInfo?.model_app_secret?.trim()
  if (!appKey || !appSecret) return null
  return `Basic ${Buffer.from(`${appKey}:${appSecret}`).toString("base64")}`
}

/**
 * Resolve a model's chat config: baseUrl (normalized with /v2) + Authorization.
 * Returns null when the model has no MaaS auth info (caller falls back to signing).
 */
function resolveModelChatConfig(model) {
  if (!model) return null
  const auth = buildMaasAuthorization(model.authInfo)
  if (!auth) return null
  const rawBase = model.apiBaseUrl || model.baseUrl || ""
  if (!rawBase) return null
  return { baseUrl: normalizeMaasBaseUrl(rawBase), authorization: auth }
}

// ---- subscription / usage --------------------------------------------------

/** Map a /v1/subscription response to magpie's usage shape. */
function usageFromSubscription(raw) {
  const data = unwrapPayload(raw) ?? raw
  if (!asRecord(data)) return { error: "OfficeAce could not be parsed", windows: [] }
  if (typeof data.code === "number" && data.code !== 0) {
    return { error: firstOf(data.message, data.msg, `OfficeAce code ${data.code}`), windows: [] }
  }

  const totalCredits = num(data.total_credits ?? data.totalCredits ?? data.total_credit)
  const usedCredits = num(data.used_credits ?? data.usedCredits ?? data.used_credit)
  const remainCredits = totalCredits > 0 ? Math.max(0, totalCredits - usedCredits) : num(data.remain_credits ?? data.remainCredits)
  const plan = firstOf(data.plan_name, data.planName, data.tier, data.spec_code)

  if (totalCredits <= 0 && usedCredits <= 0) return { plan: plan || undefined, windows: [], error: "该账号无积分额度" }

  const used = clamp(totalCredits > 0 ? (usedCredits / totalCredits) * 100 : 0)
  return {
    plan: plan || undefined,
    signIn: "kept",
    windows: [{
      name: "积分",
      used,
      display: `${formatCredit(usedCredits)} / ${formatCredit(totalCredits)}`,
      amount: usedCredits,
      limit: totalCredits,
      unit: "credits",
    }],
  }
}

/** Compact credit counts for the display string (12345 → "1.2万"). */
function formatCredit(n) {
  const v = Math.max(0, Number.isFinite(n) ? n : 0)
  if (v >= 1e8) return `${(v / 1e8).toFixed(1)}亿`
  if (v >= 1e4) return `${(v / 1e4).toFixed(1)}万`
  return String(Math.round(v))
}

// ---- the plugin -------------------------------------------------------------

export const OfficeAceAuthPlugin = async ({ client } = {}, options = {}) => {
  const fetcher = typeof options?.fetch === "function" ? options.fetch : fetch
  const env = options?.env ?? process.env

  const configModel = (m) => ({
    name: m.name ?? m.id,
    limit: { context: num(m.contextLength) || 0, output: 0 },
    tool_call: true,
  })

  const modelOf = (provider, live) => {
    const base = provider.models?.[live.id] ?? {}
    const model = {
      ...base,
      id: live.id,
      name: live.name || base.name || live.id,
      limit: { context: num(live.contextLength) || base.limit?.context || 0, output: 0 },
    }
    // Per-model chat base URL when the model carries one.
    const chatConfig = resolveModelChatConfig(live)
    if (chatConfig) model.api = chatConfig.baseUrl
    return model
  }

  return {
    // The provider and the models it has before anyone is signed in.
    config: async (config) => {
      config.provider ??= {}
      config.provider[PROVIDER] ??= {}
      const p = config.provider[PROVIDER]
      p.name ??= "OfficeAce"
      p.npm ??= NPM
      p.api ??= `${clawBase(env)}/v2`
      p.models = { ...Object.fromEntries(CATALOG.map((m) => [m.id, configModel(m)])), ...(p.models ?? {}) }
    },

    // The account's own list when signed in and OfficeAce answers.
    provider: {
      id: PROVIDER,
      async models(provider, { auth } = {}) {
        const cred = credentialOf(auth)
        if (!cred?.access_key_id) return provider.models
        try {
          const list = await fetchRemoteModels(cred, fetcher, env)
          if (!list.length) return provider.models
          return Object.fromEntries(list.map((m) => [m.id, modelOf(provider, m)]))
        } catch {
          return provider.models
        }
      },
    },

    auth: {
      provider: PROVIDER,
      refreshLead: REFRESH_LEAD_MS,
      maxConcurrency: 4,

      // magpie's own hook: renew the temporary credentials before they expire.
      async refresh(auth) {
        const cred = credentialOf(auth)
        if (!cred) return undefined
        const next = await refreshCredential(cred, tokenEndpoint(env), fetcher)
        return {
          access: JSON.stringify(next),
          refresh: next.refresh_token,
          expires: expiresFromCredential(next),
        }
      },

      // Every request the account makes is authenticated here.
      async loader(getAuth) {
        const auth = await getAuth()
        let cred = credentialOf(auth)
        if (!cred?.access_key_id || !cred?.secret_access_key) return {}

        // Refresh in-band when the credential is about to expire (for hosts
        // that ignore auth.refresh).
        let refreshing = null
        const current = async () => {
          if (!cred.refresh_token || Date.parse(cred.expires_at || 0) - Date.now() > REFRESH_LEAD_MS) return cred
          if (!refreshing) {
            refreshing = refreshCredential(cred, tokenEndpoint(env), fetcher)
              .then((next) => {
                cred = next
                void persistCredential(client, next, env)
                return next
              })
              .catch(() => cred)
              .finally(() => { refreshing = null })
          }
          return refreshing
        }

        // Cache the live model list so the chat wrapper can look up per-model
        // MaaS auth material and base URLs.
        let modelCache = null
        const modelsFor = async () => {
          if (modelCache) return modelCache
          try {
            modelCache = await fetchRemoteModels(cred, fetcher, env)
          } catch {
            modelCache = []
          }
          return modelCache
        }

        const sessionId = randomHex(16)
        return {
          baseURL: `${clawBase(env)}/v2`,
          async fetch(input, init = {}) {
            const c = await current()
            const req = typeof Request !== "undefined" && input instanceof Request ? input : null
            const url = req ? req.url : String(input)
            const method = String(init?.method ?? req?.method ?? "GET").toUpperCase()
            const headers = new Headers(init?.headers ?? req?.headers)
            let body
            if (init?.body != null) body = await toBytes(init.body)
            else if (req) body = new Uint8Array(await req.clone().arrayBuffer())
            else body = new Uint8Array()

            // Identify the model from the request body to resolve per-model
            // chat base URL + MaaS Basic auth.
            const modelId = typeof init?.body === "string" ? safeJson(init.body)?.model : undefined
            const list = await modelsFor()
            const model = modelId ? list.find((m) => m.id === modelId) : undefined
            const chatConfig = resolveModelChatConfig(model)

            let targetUrl = url
            if (chatConfig) {
              // Rewrite to the model's MaaS base + /chat/completions.
              const u = new URL(url)
              if (u.pathname.endsWith("/chat/completions") || u.pathname.includes("/chat/")) {
                targetUrl = `${chatConfig.baseUrl}/chat/completions`
              }
              headers.set("Authorization", chatConfig.authorization)
            } else {
              // Fall back to SDK-HMAC-SHA256 signing with the account's v5 credential.
              const v5 = {
                accessKey: c.access_key_id, secretKey: c.secret_access_key,
                securityToken: c.security_token, projectId: c.project_id || "",
              }
              const signed = await buildSignedHeaders({
                method, url: targetUrl, credential: v5, bodyText: body, algorithm: ALGO_SDK,
              })
              if (signed) {
                for (const [k, v] of Object.entries(signed)) {
                  if (k.toLowerCase() !== "host") headers.set(k, v)
                }
              }
            }

            headers.set("Chat-Id", randomHex(16))
            headers.set("Session-Id", sessionId)
            headers.set("lang", "en")

            const res = await fetcher(targetUrl, {
              ...init,
              method,
              headers,
              ...(body.length > 0 ? { body } : {}),
            })
            if (res.status === 401 || res.status === 403) {
              const h = new Headers(res.headers)
              h.set("X-Magpie-Sign-In", "expired")
              return new Response(res.body, { status: res.status, statusText: res.statusText, headers: h })
            }
            return res
          },
        }
      },

      // magpie's own hook: how much of the plan is left.
      async usage(getAuth) {
        const auth = await getAuth()
        const cred = credentialOf(auth)
        if (!cred?.access_key_id) return { error: "not signed in", windows: [] }
        try {
          const res = await signedGet(subscriptionUrl(env), cred, fetcher, {
            extraHeaders: { "x-subscription-type": "v2" }, env,
          })
          if (!res) return { error: "OfficeAce answered an error", windows: [] }
          return usageFromSubscription(await res.json().catch(() => null))
        } catch (e) {
          return { error: e?.message ?? String(e), windows: [] }
        }
      },

      methods: [
        {
          type: "oauth",
          label: "Sign in with Huawei Cloud",
          async authorize() {
            const flow = await startOAuthFlow(env, fetcher)
            return {
              url: flow.loginUrl,
              instructions: "Sign in to Huawei Cloud in the browser; the window completes itself when done.",
              method: "auto",
              async callback() {
                try {
                  const outcome = await flow.result
                  const cred = safeJson(outcome.access)
                  if (!cred?.access_key_id) return { type: "failed", error: "OfficeAce did not return a credential" }
                  return {
                    type: "success",
                    access: outcome.access,
                    refresh: cred.refresh_token,
                    expires: outcome.expires,
                  }
                } catch (e) {
                  return { type: "failed", error: e?.message ?? String(e) }
                }
              },
            }
          },
        },
      ],
    },
  }
}

/** Best-effort: store a freshly refreshed credential back on the account. */
async function persistCredential(client, cred, env) {
  try {
    await client?.auth?.set?.({
      path: { id: PROVIDER },
      body: {
        type: "oauth",
        access: JSON.stringify(cred),
        refresh: cred.refresh_token,
        expires: expiresFromCredential(cred),
      },
    })
  } catch {
    /* best effort */
  }
}

// for tests (never a plugin: magpie only calls exported functions)
export const _internal = {
  PROVIDER, NPM, CATALOG, REGION_ID, MODEL_PROVIDER_ID, MODEL_PAGE_SIZE, MODEL_MAX_PAGES,
  DEFAULT_CLAW_BASE, DEFAULT_AUTH_BASE, DEFAULT_IAM_BASE, DEFAULT_IAM_KEYSTONE_BASE,
  DEFAULT_CLIENT_ID, IAM_V3_DURATION_SECONDS,
  GRANT_AUTHORIZATION_CODE, GRANT_REFRESH_TOKEN,
  ALGO_SDK, ALGO_V11,
  clawBase, authBaseUrl, iamTokenBase, iamKeystoneBase, iamSecurityTokenUrl,
  redirectUri, tokenEndpoint, stateEndpoint, codePollUrl, modelServicesUrl,
  subscribeUrl, subscriptionUrl, subscriptionUsageUrl, permissionValidateUrl,
  firstOf, asRecord, safeJson, num, clamp, prettify, stripTrailingSlash, firstEnv,
  normalizeMaasBaseUrl, formatCredit,
  b64url, utf8, sha256Hex, hmacSha256Hex, sdkDate, rfc3986Encode, canonicalUri, canonicalQuery,
  lowerHeaders, buildCanonicalRequest, sdkAuthorization, v11Authorization, v11SigningKey,
  buildSignedHeaders, unwrapPayload, readStringField,
  exchangeIamV3SecurityToken, resolveV3Credential, v3Expired, fetchSigned,
  generatePkcePair, generateDpopKeyPair, keyPairFromStoredJwk, signDpopJws,
  credentialFromTokenResponse, credentialOf, expiresFromCredential,
  requestToken, exchangeAuthorizationCode, exchangeRefreshToken, refreshCredential,
  requestState, buildOAuthLoginUrl, pollForCode, startOAuthFlow,
  toBytes, signedGet,
  parseModelInfo, fetchRemoteModels,
  buildMaasAuthorization, resolveModelChatConfig,
  usageFromSubscription,
}
