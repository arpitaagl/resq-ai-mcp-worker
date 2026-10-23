import { createRemoteJWKSet, jwtVerify } from "jose";

export interface Auth0Env {
	AUTH0_DOMAIN: string;
	AUTH0_CLIENT_ID: string;
	AUTH0_CLIENT_SECRET: string;
}

export interface UpstreamAuthData {
	codeVerifier: string;
	nonce: string;
}

const jwksCache = new Map<string, ReturnType<typeof createRemoteJWKSet>>();

function auth0Issuer(domainValue: string): string {
	const value = domainValue.trim();
	const host = value.replace(/^https:\/\//i, "").replace(/\/+$/, "");
	if (!host || /[/:?#@\s]/.test(host)) {
		throw new Error("AUTH0_DOMAIN must be an Auth0 hostname, without a path.");
	}
	const url = new URL(`https://${host}/`);
	if (url.hostname !== host.toLowerCase() || url.port) {
		throw new Error("AUTH0_DOMAIN must be an Auth0 hostname, without a port.");
	}
	return url.href;
}

export function auth0AuthorizeUrl(env: Auth0Env): URL {
	if (!env.AUTH0_CLIENT_ID) {
		throw new Error("Auth0 client configuration is missing.");
	}
	const issuer = auth0Issuer(env.AUTH0_DOMAIN);
	const url = new URL("authorize", issuer);
	url.searchParams.set("client_id", env.AUTH0_CLIENT_ID);
	url.searchParams.set("response_type", "code");
	url.searchParams.set("scope", "openid");
	return url;
}

export async function exchangeAuth0Code(
	code: string,
	codeVerifier: string,
	redirectUri: string,
	env: Auth0Env,
): Promise<{
	userId: string;
	nonce: string;
}> {
	if (!env.AUTH0_CLIENT_ID || !env.AUTH0_CLIENT_SECRET) {
		throw new Error("Auth0 client configuration is missing.");
	}
	if (
		!code ||
		!/^[A-Za-z0-9\-._~]{43,128}$/.test(codeVerifier) ||
		new URL(redirectUri).pathname !== "/callback"
	) {
		throw new Error("Invalid Auth0 authorization-code exchange parameters.");
	}
	const issuer = auth0Issuer(env.AUTH0_DOMAIN);
	const tokenUrl = new URL("oauth/token", issuer);
	const response = await fetch(tokenUrl, {
		method: "POST",
		headers: { "content-type": "application/x-www-form-urlencoded" },
		body: new URLSearchParams({
			grant_type: "authorization_code",
			client_id: env.AUTH0_CLIENT_ID,
			client_secret: env.AUTH0_CLIENT_SECRET,
			code,
			code_verifier: codeVerifier,
			redirect_uri: redirectUri,
		}),
		signal: AbortSignal.timeout(10_000),
	});
	if (!response.ok) {
		// Do not include the provider response, code, or credentials in thrown errors.
		throw new Error("Auth0 authorization-code exchange failed.");
	}

	const tokens: unknown = await response.json();
	if (
		typeof tokens !== "object" ||
		tokens === null ||
		!("id_token" in tokens) ||
		typeof tokens.id_token !== "string"
	) {
		throw new Error("Auth0 did not return an ID token.");
	}

	return verifyAuth0IdToken(tokens.id_token, env, issuer);
}

async function verifyAuth0IdToken(idToken: string, env: Auth0Env, expectedIssuer: string) {
	let jwks = jwksCache.get(expectedIssuer);
	if (!jwks) {
		jwks = createRemoteJWKSet(new URL(".well-known/jwks.json", expectedIssuer));
		jwksCache.set(expectedIssuer, jwks);
	}

	const { payload } = await jwtVerify(idToken, jwks, {
		issuer: expectedIssuer,
		audience: env.AUTH0_CLIENT_ID,
		algorithms: ["RS256"],
	});

	if (
		typeof payload.nonce !== "string" ||
		typeof payload.sub !== "string" ||
		payload.sub.length === 0 ||
		(payload.azp !== undefined && payload.azp !== env.AUTH0_CLIENT_ID) ||
		(Array.isArray(payload.aud) &&
			payload.aud.length > 1 &&
			payload.azp !== env.AUTH0_CLIENT_ID)
	) {
		throw new Error("Auth0 ID-token claims validation failed.");
	}

	return {
		userId: payload.sub,
		nonce: payload.nonce,
	};
}

export async function verifyAuth0IdTokenNonce(
	idTokenResult: Awaited<ReturnType<typeof exchangeAuth0Code>>,
	expectedNonce: string,
) {
	if (!expectedNonce || idTokenResult.nonce !== expectedNonce) {
		throw new Error("Auth0 ID-token nonce validation failed.");
	}
	const { nonce: _nonce, ...identity } = idTokenResult;
	return identity;
}
