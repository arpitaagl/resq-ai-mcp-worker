import {
	AuthorizationError,
	CimdFetchError,
	authorizationErrorRedirect,
	type OAuthHelpers,
} from "@cloudflare/workers-oauth-provider";
import {
	auth0AuthorizeUrl,
	exchangeAuth0Code,
	verifyAuth0IdTokenNonce,
	type Auth0Env,
	type UpstreamAuthData,
} from "./auth";

export type RuntimeEnv = Env &
	Auth0Env & {
		MCP_PUBLIC_URL: string;
		OAUTH_PROVIDER: OAuthHelpers;
	};

const callbackPath = "/callback";

const escapeHtml = (value: string) =>
	value.replace(/[&<>"']/g, (char) => `&#${char.charCodeAt(0)};`);

function consentHtml(
	details: Awaited<ReturnType<OAuthHelpers["describeConsent"]>>,
	handle: string,
) {
	const scopes = details.scope
		.map(
			(scope) =>
				`<label><input type="checkbox" name="scope" value="${escapeHtml(scope)}" checked> ${escapeHtml(scope)}</label>`,
		)
		.join("<br>");
	const domain = details.clientDomain
		? `Published by <strong>${escapeHtml(details.clientDomain)}</strong>.`
		: "This app registered itself; its name is not verified.";
	return `<!doctype html><html><head><meta charset="utf-8"><title>Authorize ${escapeHtml(details.clientName)}</title></head><body><h1>Allow ${escapeHtml(details.clientName)} to access your ResQ-AI account?</h1><p>${domain} Access will be sent to <strong>${escapeHtml(details.redirectHost)}</strong>.</p>${details.redirectIsLoopback ? "<p><strong>This sends access to an app on your computer.</strong> Continue only if you just started signing in from it.</p>" : ""}<form method="post"><input type="hidden" name="handle" value="${escapeHtml(handle)}">${scopes}<p><button name="decision" value="approve">Allow</button> <button name="decision" value="deny">Deny</button></p></form></body></html>`;
}

function localAuthorizationError(error: unknown): Response | undefined {
	if (error instanceof AuthorizationError && error.redirectTo) {
		return Response.redirect(error.redirectTo, 302);
	}
	if (error instanceof AuthorizationError || error instanceof CimdFetchError) {
		const message =
			error instanceof AuthorizationError
				? error.description
				: "This app could not be verified. Please try again.";
		return new Response(escapeHtml(message), {
			status: 400,
			headers: { "content-type": "text/plain; charset=utf-8" },
		});
	}
	return undefined;
}

export type PublicUrlErrorCategory = "missing" | "malformed" | "canonical_origin_rejected";
export type PublicUrlDiagnosticCategory = PublicUrlErrorCategory | "unexpected";

export class PublicUrlConfigurationError extends Error {
	readonly category: PublicUrlErrorCategory;

	constructor(category: PublicUrlErrorCategory) {
		super("MCP_PUBLIC_URL must be a canonical HTTPS origin.");
		this.name = "PublicUrlConfigurationError";
		this.category = category;
	}
}

export function publicUrlDiagnosticCategory(error: unknown): PublicUrlDiagnosticCategory {
	return error instanceof PublicUrlConfigurationError ? error.category : "unexpected";
}

function canonicalOrigin(value: string): URL {
	if (typeof value !== "string" || value.length === 0) {
		throw new PublicUrlConfigurationError("missing");
	}

	let url: URL;
	try {
		url = new URL(value);
	} catch {
		throw new PublicUrlConfigurationError("malformed");
	}
	const localHttp =
		url.protocol === "http:" &&
		(url.hostname === "localhost" ||
			url.hostname.startsWith("127.") ||
			url.hostname === "[::1]");
	if (
		(url.protocol !== "https:" && !localHttp) ||
		url.origin !== value ||
		url.username ||
		url.password ||
		url.pathname !== "/" ||
		url.search ||
		url.hash
	) {
		throw new PublicUrlConfigurationError("canonical_origin_rejected");
	}
	return url;
}

async function handleAuthorization(request: Request, env: RuntimeEnv) {
	const oauth = env.OAUTH_PROVIDER;
	try {
		if (request.method === "GET") {
			const authRequest = await oauth.parseAuthRequest(request);
			if (!authRequest.codeChallenge || authRequest.codeChallengeMethod !== "S256") {
				throw new AuthorizationError("invalid_request", {
					description: "Authorization code flow requires S256 PKCE.",
				});
			}
			const details = await oauth.describeConsent(authRequest);
			const consent = await oauth.beginConsent(authRequest);
			consent.headers.set("content-type", "text/html; charset=utf-8");
			consent.headers.set("cache-control", "no-store");
			return new Response(consentHtml(details, consent.handle), {
				headers: consent.headers,
			});
		}

		if (request.method !== "POST") {
			return new Response("Method not allowed", {
				status: 405,
				headers: { allow: "GET, POST" },
			});
		}

		const form = await request.formData();
		const handle = String(form.get("handle") ?? "");
		if (form.get("decision") !== "approve") {
			const denied = await oauth.denyConsent(request, handle);
			return new Response(null, { status: 302, headers: denied.headers });
		}

		const approved = await oauth.approveConsent(request, handle, {
			scope: form.getAll("scope").map(String),
		});
		const verifier = randomToken();
		const nonce = randomToken();
		const { state, headers } = await oauth.beginUpstream(approved.request, {
			data: { codeVerifier: verifier, nonce } satisfies UpstreamAuthData,
			headers: approved.headers,
		});

		const authorizeUrl = auth0AuthorizeUrl(env);
		authorizeUrl.searchParams.set(
			"redirect_uri",
			new URL(callbackPath, env.MCP_PUBLIC_URL).href,
		);
		authorizeUrl.searchParams.set("state", state);
		authorizeUrl.searchParams.set("nonce", nonce);
		authorizeUrl.searchParams.set("code_challenge", await pkceChallenge(verifier));
		authorizeUrl.searchParams.set("code_challenge_method", "S256");
		headers.set("location", authorizeUrl.href);
		return new Response(null, { status: 302, headers });
	} catch (error) {
		const response = localAuthorizationError(error);
		if (response) return response;
		throw error;
	}
}

async function handleAuth0Callback(request: Request, env: RuntimeEnv) {
	const oauth = env.OAUTH_PROVIDER;
	try {
		const {
			request: authRequest,
			data,
			headers,
		} = await oauth.finishUpstream<UpstreamAuthData>(request);
		const params = new URL(request.url).searchParams;
		if (params.has("error")) {
			headers.set("location", authorizationErrorRedirect(authRequest, "access_denied"));
			return new Response(null, { status: 302, headers });
		}

		const code = params.get("code");
		if (!code || !data?.codeVerifier || !data.nonce) {
			throw new Error("Incomplete Auth0 callback.");
		}
		const identityWithNonce = await exchangeAuth0Code(
			code,
			data.codeVerifier,
			new URL(callbackPath, env.MCP_PUBLIC_URL).href,
			env,
		);
		const identity = await verifyAuth0IdTokenNonce(identityWithNonce, data.nonce);
		const { redirectTo } = await oauth.completeAuthorization({
			request: authRequest,
			// OAuth Provider 1.2.4 reserves ':' as its internal token delimiter.
			userId: encodeURIComponent(identity.userId),
			metadata: {},
			scope: authRequest.scope,
			props: { userId: identity.userId },
		});
		headers.set("location", redirectTo);
		return new Response(null, { status: 302, headers });
	} catch (error) {
		const response = localAuthorizationError(error);
		if (response) return response;
		throw error;
	}
}

function randomToken() {
	const bytes = crypto.getRandomValues(new Uint8Array(32));
	let binary = "";
	for (const byte of bytes) binary += String.fromCharCode(byte);
	return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

async function pkceChallenge(verifier: string) {
	const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(verifier));
	let binary = "";
	for (const byte of new Uint8Array(digest)) binary += String.fromCharCode(byte);
	return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

export function createOAuthHandlers(
	mcpHandler: (
		request: Request,
		env: RuntimeEnv,
		ctx: ExecutionContext,
	) => Response | Promise<Response>,
) {
	const defaultHandler: ExportedHandler<RuntimeEnv> = {
		async fetch(request, env) {
			const path = new URL(request.url).pathname;
			if (path === "/authorize") return handleAuthorization(request, env);
			if (path === callbackPath) return handleAuth0Callback(request, env);
			return new Response("Not found", { status: 404 });
		},
	};

	const apiHandler = {
		fetch(request: Request, env: RuntimeEnv, ctx: ExecutionContext) {
			const auth = (ctx as ExecutionContext & { auth?: { scope?: string[] } }).auth;
			if (!auth?.scope?.includes("mcp:read")) {
				return Response.json(
					{ error: "insufficient_scope", required_scope: "mcp:read" },
					{
						status: 403,
						headers: {
							"www-authenticate":
								'Bearer error="insufficient_scope", scope="mcp:read"',
						},
					},
				);
			}
			return mcpHandler(request, env, ctx);
		},
	};

	return { defaultHandler, apiHandler };
}

export function getCanonicalOrigin(value: string): URL {
	return canonicalOrigin(value);
}

export function isCanonicalOriginRequest(request: Request, origin: URL): boolean {
	return new URL(request.url).origin === origin.origin;
}
