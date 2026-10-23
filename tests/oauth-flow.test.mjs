import assert from "node:assert/strict";
import { createHash, randomUUID } from "node:crypto";
import { readFile } from "node:fs/promises";
import test from "node:test";
import { exportJWK, generateKeyPair, SignJWT } from "jose";
import ts from "typescript";
import { OAuthProvider, getOAuthApi } from "@cloudflare/workers-oauth-provider";
import { exchangeAuth0Code, verifyAuth0IdTokenNonce } from "../src/auth.ts";
import worker from "../src/index.ts";
import {
	createOAuthHandlers,
	getCanonicalOrigin,
	isCanonicalOriginRequest,
	PublicUrlConfigurationError,
	publicUrlDiagnosticCategory,
} from "../src/oauth-handlers.ts";

const publicUrl = "https://resq.example";
const resource = `${publicUrl}/mcp`;

class MemoryKV {
	#values = new Map();

	async get(key, options) {
		const value = this.#values.get(key);
		if (value === undefined) return null;
		return options?.type === "json" ? JSON.parse(value) : value;
	}

	async put(key, value) {
		this.#values.set(key, String(value));
	}

	async delete(key) {
		this.#values.delete(key);
	}

	async list({ prefix = "", limit = 1000 } = {}) {
		const keys = [...this.#values.keys()]
			.filter((name) => name.startsWith(prefix))
			.slice(0, limit)
			.map((name) => ({ name }));
		return { keys, list_complete: true, cursor: "" };
	}
}

function createHarness() {
	let mcpCalls = 0;
	const handlers = createOAuthHandlers(async () => {
		mcpCalls++;
		return Response.json({ toolsReached: true });
	});
	const options = {
		apiRoute: "/mcp",
		apiHandler: handlers.apiHandler,
		defaultHandler: handlers.defaultHandler,
		authorizeEndpoint: "/authorize",
		tokenEndpoint: "/oauth/token",
		clientRegistrationEndpoint: "/oauth/register",
		clientIdMetadataDocumentEnabled: true,
		scopesSupported: ["mcp:read"],
		requiredScopes: ["mcp:read"],
		resourceMetadata: {
			resource,
			authorization_servers: [publicUrl],
			resource_name: "ResQ-AI MCP Worker",
		},
		refreshTokenTTL: 0,
	};
	const env = {
		OAUTH_KV: new MemoryKV(),
		MCP_PUBLIC_URL: publicUrl,
		AUTH0_DOMAIN: `tenant-${randomUUID()}.auth0.example`,
		AUTH0_CLIENT_ID: "auth0-test-client",
		AUTH0_CLIENT_SECRET: "test-only-secret",
	};
	const provider = new OAuthProvider(options);
	const context = {
		waitUntil() {},
		passThroughOnException() {},
	};
	const fetch = (request) => provider.fetch(request, env, context);
	const helpers = getOAuthApi(options, env);
	return { env, fetch, helpers, handlers, getMcpCalls: () => mcpCalls };
}

function s256(value) {
	return createHash("sha256").update(value).digest("base64url");
}

function cookiePair(response, startsWith) {
	const cookie = response.headers.getSetCookie().find((value) => value.startsWith(startsWith));
	assert.ok(cookie, `expected ${startsWith} cookie`);
	return cookie.split(";", 1)[0];
}

async function startAuthorization(harness, client, verifier, scope = "mcp:read") {
	const params = new URLSearchParams({
		response_type: "code",
		client_id: client.clientId,
		redirect_uri: client.redirectUris[0],
		state: "client-state-value",
		resource,
		code_challenge: s256(verifier),
		code_challenge_method: "S256",
	});
	if (scope) params.set("scope", scope);
	const response = await harness.fetch(
		new Request(`${publicUrl}/authorize?${params}`, { redirect: "manual" }),
	);
	return response;
}

test("OAuth Provider 1.2.4 consent, upstream state, Auth0 exchange, PKCE, scope, and MCP protection", async () => {
	const harness = createHarness();
	const metadataResponse = await harness.fetch(
		new Request(`${publicUrl}/.well-known/oauth-authorization-server`),
	);
	assert.equal(metadataResponse.status, 200);
	const metadata = await metadataResponse.json();
	assert.equal(metadata.issuer, publicUrl);
	assert.equal(metadata.authorization_endpoint, `${publicUrl}/authorize`);
	assert.equal(metadata.token_endpoint, `${publicUrl}/oauth/token`);
	assert.equal(metadata.registration_endpoint, `${publicUrl}/oauth/register`);
	assert.equal(metadata.client_id_metadata_document_supported, true);
	const resourceMetadataResponse = await harness.fetch(
		new Request(`${publicUrl}/.well-known/oauth-protected-resource/mcp`),
	);
	assert.equal(resourceMetadataResponse.status, 200);
	const resourceMetadata = await resourceMetadataResponse.json();
	assert.equal(resourceMetadata.resource, resource);
	assert.deepEqual(resourceMetadata.authorization_servers, [publicUrl]);
	assert.deepEqual(resourceMetadata.scopes_supported, ["mcp:read"]);

	const confidentialClient = await harness.helpers.createClient({
		clientName: "Confidential client without PKCE",
		redirectUris: ["http://127.0.0.1:8788/callback"],
		grantTypes: ["authorization_code"],
		responseTypes: ["code"],
		tokenEndpointAuthMethod: "client_secret_post",
	});
	const noPkce = new URLSearchParams({
		response_type: "code",
		client_id: confidentialClient.clientId,
		redirect_uri: confidentialClient.redirectUris[0],
		state: "no-pkce-state",
		resource,
		scope: "mcp:read",
	});
	const noPkceResponse = await harness.fetch(new Request(`${publicUrl}/authorize?${noPkce}`));
	assert.equal(noPkceResponse.status, 400);
	assert.match(await noPkceResponse.text(), /requires S256 PKCE/);

	const registrationResponse = await harness.fetch(
		new Request(`${publicUrl}/oauth/register`, {
			method: "POST",
			headers: { "content-type": "application/json" },
			body: JSON.stringify({
				client_name: "ResQ flow test client",
				redirect_uris: ["http://127.0.0.1:8788/callback"],
				grant_types: ["authorization_code"],
				response_types: ["code"],
				token_endpoint_auth_method: "none",
			}),
		}),
	);
	assert.equal(registrationResponse.status, 201);
	const registration = await registrationResponse.json();
	assert.ok(registration.client_id);
	assert.equal(registration.token_endpoint_auth_method, "none");
	const client = {
		clientId: registration.client_id,
		redirectUris: registration.redirect_uris,
	};

	const unauthenticated = await harness.fetch(new Request(`${publicUrl}/mcp`));
	assert.equal(unauthenticated.status, 401);
	assert.equal(harness.getMcpCalls(), 0);

	const mcpVerifier = "mcp-client-verifier-value-with-at-least-43-chars";
	const consentPage = await startAuthorization(harness, client, mcpVerifier);
	assert.equal(consentPage.status, 200);
	assert.match(consentPage.headers.get("content-security-policy"), /frame-ancestors 'none'/);
	assert.match(consentPage.headers.get("x-frame-options"), /DENY/);
	const consentCookie = cookiePair(consentPage, "__Host-oauth-consent-");
	const html = await consentPage.text();
	const handle = html.match(/name="handle" value="([^"]+)"/)?.[1];
	assert.ok(handle);
	assert.match(html, /127\.0\.0\.1/);

	const forgedPost = await harness.fetch(
		new Request(`${publicUrl}/authorize`, {
			method: "POST",
			headers: { "content-type": "application/x-www-form-urlencoded" },
			body: new URLSearchParams({ handle, decision: "approve", scope: "mcp:read" }),
		}),
	);
	assert.equal(forgedPost.status, 400);

	const approved = await harness.fetch(
		new Request(`${publicUrl}/authorize`, {
			method: "POST",
			headers: {
				cookie: consentCookie,
				"content-type": "application/x-www-form-urlencoded",
			},
			body: new URLSearchParams({ handle, decision: "approve", scope: "mcp:read" }),
			redirect: "manual",
		}),
	);
	assert.equal(approved.status, 302);
	const auth0Url = new URL(approved.headers.get("location"));
	assert.equal(auth0Url.origin, `https://${harness.env.AUTH0_DOMAIN}`);
	assert.equal(auth0Url.searchParams.get("redirect_uri"), `${publicUrl}/callback`);
	assert.equal(auth0Url.searchParams.get("scope"), "openid");
	assert.equal(auth0Url.searchParams.get("code_challenge_method"), "S256");
	const upstreamState = auth0Url.searchParams.get("state");
	const upstreamCookie = cookiePair(approved, "__Host-oauth-upstream-");
	assert.ok(upstreamState);

	let exchangeBody;
	let tokenExchangeCount = 0;
	const originalFetch = globalThis.fetch;
	const { privateKey, publicKey } = await generateKeyPair("RS256");
	const jwk = await exportJWK(publicKey);
	jwk.kid = "test-key";
	jwk.use = "sig";
	jwk.alg = "RS256";
	const nonce = auth0Url.searchParams.get("nonce");
	const idToken = await new SignJWT({ nonce })
		.setProtectedHeader({ alg: "RS256", kid: "test-key" })
		.setIssuer(`https://${harness.env.AUTH0_DOMAIN}/`)
		.setAudience(harness.env.AUTH0_CLIENT_ID)
		.setSubject("auth0:subject:contains-colons")
		.setIssuedAt()
		.setExpirationTime("5m")
		.sign(privateKey);
	globalThis.fetch = async (input, init = {}) => {
		const url = new URL(input);
		if (url.pathname === "/oauth/token") {
			tokenExchangeCount++;
			exchangeBody = new URLSearchParams(init.body);
			return Response.json({ id_token: idToken });
		}
		if (url.pathname === "/.well-known/jwks.json") {
			return Response.json({ keys: [jwk] });
		}
		throw new Error(`Unexpected test fetch to ${url.origin}${url.pathname}`);
	};

	try {
		const missingCookie = await harness.fetch(
			new Request(
				`${publicUrl}/callback?state=${encodeURIComponent(upstreamState)}&code=one-time-code`,
				{ redirect: "manual" },
			),
		);
		assert.equal(missingCookie.status, 400);
		assert.equal(tokenExchangeCount, 0);

		const wrongState = await harness.fetch(
			new Request(`${publicUrl}/callback?state=wrong-state&code=one-time-code`, {
				headers: { cookie: upstreamCookie },
				redirect: "manual",
			}),
		);
		assert.equal(wrongState.status, 400);
		assert.equal(tokenExchangeCount, 0);

		const callback = await harness.fetch(
			new Request(
				`${publicUrl}/callback?state=${encodeURIComponent(upstreamState)}&code=one-time-code`,
				{ headers: { cookie: upstreamCookie }, redirect: "manual" },
			),
		);
		assert.equal(callback.status, 302);
		assert.equal(tokenExchangeCount, 1);
		assert.equal(exchangeBody.get("grant_type"), "authorization_code");
		assert.equal(exchangeBody.get("client_id"), harness.env.AUTH0_CLIENT_ID);
		assert.equal(exchangeBody.get("client_secret"), harness.env.AUTH0_CLIENT_SECRET);
		assert.equal(exchangeBody.get("code_verifier").length, 43);
		assert.equal(
			s256(exchangeBody.get("code_verifier")),
			auth0Url.searchParams.get("code_challenge"),
		);
		assert.equal(exchangeBody.get("redirect_uri"), `${publicUrl}/callback`);
		assert.match(callback.headers.get("location"), /^http:\/\/127\.0\.0\.1:8788\/callback\?/);
		assert.equal(
			new URL(callback.headers.get("location")).searchParams.get("state"),
			"client-state-value",
		);

		const clientCode = new URL(callback.headers.get("location")).searchParams.get("code");
		const tokenResponse = await harness.fetch(
			new Request(`${publicUrl}/oauth/token`, {
				method: "POST",
				headers: { "content-type": "application/x-www-form-urlencoded" },
				body: new URLSearchParams({
					grant_type: "authorization_code",
					client_id: client.clientId,
					code: clientCode,
					code_verifier: mcpVerifier,
					resource,
				}),
			}),
		);
		assert.equal(tokenResponse.status, 200);
		const token = (await tokenResponse.json()).access_token;
		assert.ok(token);
		assert.match(token, /^auth0%3Asubject%3Acontains-colons:/);

		const invalidBearer = await harness.fetch(
			new Request(`${publicUrl}/mcp`, {
				headers: { authorization: "Bearer invalid-token" },
			}),
		);
		assert.equal(invalidBearer.status, 401);
		assert.equal(harness.getMcpCalls(), 0);

		const authenticated = await harness.fetch(
			new Request(`${publicUrl}/mcp`, {
				method: "POST",
				headers: { authorization: `Bearer ${token}` },
			}),
		);
		assert.equal(authenticated.status, 200);
		assert.deepEqual(await authenticated.json(), { toolsReached: true });
		assert.equal(harness.getMcpCalls(), 1);

		const noScope = await harness.handlers.apiHandler.fetch(
			new Request(`${publicUrl}/mcp`),
			harness.env,
			{ auth: { scope: [] } },
		);
		assert.equal(noScope.status, 403);
		assert.match(noScope.headers.get("www-authenticate"), /insufficient_scope/);
		assert.equal(harness.getMcpCalls(), 1);
	} finally {
		globalThis.fetch = originalFetch;
	}
});

test("the nonce claim must match the browser-bound upstream nonce", async () => {
	await assert.rejects(
		verifyAuth0IdTokenNonce({ userId: "auth0|user", nonce: "issued-nonce" }, "expected-nonce"),
		/nonce validation failed/,
	);
	await assert.rejects(
		verifyAuth0IdTokenNonce({ userId: "auth0|user", nonce: "issued-nonce" }, ""),
		/nonce validation failed/,
	);
});

test("Auth0 ID-token issuer, audience, and signature failures are rejected", async () => {
	const originalFetch = globalThis.fetch;
	const { privateKey, publicKey } = await generateKeyPair("RS256");
	const { privateKey: attackerKey } = await generateKeyPair("RS256");
	const jwk = await exportJWK(publicKey);
	jwk.kid = "auth0-fixture-key";
	jwk.use = "sig";
	jwk.alg = "RS256";

	try {
		for (const failure of ["issuer", "audience", "signature"]) {
			const domain = `tenant-${randomUUID()}.auth0.example`;
			const expectedIssuer = `https://${domain}/`;
			const idToken = await new SignJWT({ nonce: "expected-nonce" })
				.setProtectedHeader({ alg: "RS256", kid: "auth0-fixture-key" })
				.setIssuer(failure === "issuer" ? "https://attacker.example/" : expectedIssuer)
				.setAudience(failure === "audience" ? "different-client" : "client-id")
				.setSubject("auth0|fixture")
				.setIssuedAt()
				.setExpirationTime("5m")
				.sign(failure === "signature" ? attackerKey : privateKey);
			globalThis.fetch = async (input) => {
				const url = new URL(input);
				if (url.pathname === "/oauth/token") return Response.json({ id_token: idToken });
				if (url.pathname === "/.well-known/jwks.json")
					return Response.json({ keys: [jwk] });
				throw new Error(`Unexpected test fetch to ${url.href}`);
			};
			await assert.rejects(
				exchangeAuth0Code("code", "x".repeat(43), `${publicUrl}/callback`, {
					AUTH0_DOMAIN: domain,
					AUTH0_CLIENT_ID: "client-id",
					AUTH0_CLIENT_SECRET: "secret",
				}),
			);
		}
	} finally {
		globalThis.fetch = originalFetch;
	}
});

test("Auth0 code exchange rejects bad PKCE parameters and never exposes response secrets", async () => {
	const env = {
		AUTH0_DOMAIN: "tenant.auth0.example",
		AUTH0_CLIENT_ID: "client-id",
		AUTH0_CLIENT_SECRET: "client-secret",
	};
	await assert.rejects(
		exchangeAuth0Code("auth-code", "short", `${publicUrl}/callback`, env),
		/Invalid Auth0 authorization-code exchange parameters/,
	);
	await assert.rejects(
		exchangeAuth0Code("auth-code", "x".repeat(43), `${publicUrl}/not-callback`, env),
		/Invalid Auth0 authorization-code exchange parameters/,
	);
});

test("canonical public URL rejects host/path ambiguity and accepts HTTPS or loopback HTTP", () => {
	assert.equal(getCanonicalOrigin("https://resq.example").origin, "https://resq.example");
	assert.equal(getCanonicalOrigin("http://localhost:8787").origin, "http://localhost:8787");
	assert.throws(() => getCanonicalOrigin("https://resq.example/other"), /canonical HTTPS origin/);
	assert.throws(() => getCanonicalOrigin("http://example.com"), /canonical HTTPS origin/);
	const origin = getCanonicalOrigin("https://resq.example");
	assert.equal(isCanonicalOriginRequest(new Request(`${publicUrl}/mcp`), origin), true);
	assert.equal(
		isCanonicalOriginRequest(new Request("https://attacker.example/mcp"), origin),
		false,
	);
});

test("public URL configuration failures expose only fixed diagnostic categories", () => {
	const assertCategory = (value, category) => {
		assert.throws(
			() => getCanonicalOrigin(value),
			(error) => error instanceof PublicUrlConfigurationError && error.category === category,
		);
	};

	assertCategory("", "missing");
	assertCategory("not a URL", "malformed");
	assertCategory("http://example.invalid", "canonical_origin_rejected");
	assert.equal(publicUrlDiagnosticCategory(new Error("unexpected test failure")), "unexpected");
});

test("dynamic registration rejects non-loopback HTTP redirect URIs", async () => {
	const harness = createHarness();
	const response = await harness.fetch(
		new Request(`${publicUrl}/oauth/register`, {
			method: "POST",
			headers: { "content-type": "application/json" },
			body: JSON.stringify({
				client_name: "Invalid redirect test client",
				redirect_uris: ["http://app.example/callback"],
				grant_types: ["authorization_code"],
				response_types: ["code"],
				token_endpoint_auth_method: "none",
			}),
		}),
	);

	assert.equal(response.status, 400);
	const body = await response.json();
	assert.equal(body.error, "invalid_client_metadata");
	assert.equal("client_id" in body, false);
});

test("Worker logs safe public URL diagnostics for missing, malformed, and rejected values", async () => {
	const scenarios = [
		{ value: undefined, configured: false, category: "missing" },
		{ value: "not a URL", configured: true, category: "malformed" },
		{
			value: "http://example.invalid",
			configured: true,
			category: "canonical_origin_rejected",
		},
	];
	const originalConsoleError = console.error;

	try {
		for (const scenario of scenarios) {
			const diagnostics = [];
			console.error = (...args) => diagnostics.push(args);
			const response = await worker.fetch(
				new Request("http://localhost:8787/authorize"),
				{ MCP_PUBLIC_URL: scenario.value },
				{},
			);

			assert.equal(response.status, 500);
			assert.equal(diagnostics.length, 1);
			assert.equal(diagnostics[0][0], "MCP_PUBLIC_URL configuration diagnostic");
			assert.deepEqual(diagnostics[0][1], {
				configured: scenario.configured,
				category: scenario.category,
			});
			assert.deepEqual(Object.keys(diagnostics[0][1]).sort(), ["category", "configured"]);
		}
	} finally {
		console.error = originalConsoleError;
	}
});

test("Worker accepts a valid configured origin and rejects a different request origin", async () => {
	const env = { MCP_PUBLIC_URL: publicUrl, OAUTH_KV: new MemoryKV() };
	const metadataResponse = await worker.fetch(
		new Request(`${publicUrl}/.well-known/oauth-authorization-server`),
		env,
		{},
	);
	assert.equal(metadataResponse.status, 200);
	assert.equal((await metadataResponse.json()).issuer, publicUrl);

	const misdirectedResponse = await worker.fetch(
		new Request("http://localhost:8787/authorize"),
		env,
		{},
	);
	assert.equal(misdirectedResponse.status, 421);
});

test("the incident tools and priority formula match the preserved pre-auth backup", async () => {
	const current = await readFile(new URL("../src/index.ts", import.meta.url), "utf8");
	const backup = await readFile(new URL("../src/index.ts.oauth-backup", import.meta.url), "utf8");
	const toolSection = (source) => {
		const ast = ts.createSourceFile("tools.ts", source, ts.ScriptTarget.Latest, true);
		const start = ast.statements.findIndex(
			(statement) =>
				ts.isTypeAliasDeclaration(statement) && statement.name.text === "Incident",
		);
		const end = ast.statements.findIndex(
			(statement) =>
				ts.isFunctionDeclaration(statement) && statement.name?.text === "createServer",
		);
		assert.notEqual(start, -1);
		assert.notEqual(end, -1);
		const serialize = (node) => {
			const children = [];
			node.forEachChild((child) => children.push(serialize(child)));
			const isTextLiteral =
				ts.isIdentifier(node) || ts.isStringLiteral(node) || ts.isNumericLiteral(node);
			return [node.kind, isTextLiteral ? node.text : null, children];
		};
		return ast.statements.slice(start, end + 1).map(serialize);
	};
	assert.deepEqual(toolSection(current), toolSection(backup));
	assert.equal((current.match(/server\.registerTool\(/g) ?? []).length, 7);
	assert.match(current, /severity \* 20 \+ Math\.min\(incident\.peopleAffected, 200\) \/ 10/);
});
