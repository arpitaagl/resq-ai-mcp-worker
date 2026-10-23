# ResQ-AI MCP Worker

This Cloudflare Worker exposes seven read-only ResQ-AI MCP tools and protects
them with the Cloudflare Workers OAuth Provider. Users sign in through Auth0;
MCP clients receive Worker-issued access tokens for the `/mcp` resource. The
Worker keeps only the verified Auth0 subject in its grant and does not request
or retain Auth0 refresh tokens.

## Configure Auth0

Create an Auth0 Regular Web Application and configure its Allowed Callback URL
as `https://<your-worker-host>/callback`. Set these Worker variables:

- `AUTH0_DOMAIN`: your Auth0 tenant hostname, such as `example.us.auth0.com`
- `AUTH0_CLIENT_ID`: the application's client ID
- `MCP_PUBLIC_URL`: the canonical Worker origin, such as
  `https://resq-ai.example.com` (no path or trailing slash)
- `AUTH0_CLIENT_SECRET`: the application's client secret, stored as a Worker
  secret (for example, with `wrangler secret put AUTH0_CLIENT_SECRET`)

The `/authorize` endpoint shows a browser-bound consent page before redirecting
to Auth0. The callback validates the OAuth state, upstream PKCE verifier, Auth0
ID-token signature, issuer, audience, and nonce before issuing a Worker token.
The Cloudflare `OAUTH_KV` binding stores OAuth protocol data. Configure the
existing KV namespace in `wrangler.jsonc` for each deployment environment.

The configured `MCP_PUBLIC_URL` pins the OAuth issuer, callback, and protected
resource metadata to one hostname. Requests on other hostnames are rejected.
The protected resource identifier is `<MCP_PUBLIC_URL>/mcp`. For local
development, use the Wrangler local origin (for example,
`http://localhost:8787`) and add that callback to the Auth0 application's
Allowed Callback URLs. MCP calls require a valid Worker access token with the
`mcp:read` scope.

OAuth metadata advertises Dynamic Client Registration at `/oauth/register` and
Client ID Metadata Documents. The Wrangler `global_fetch_strictly_public` flag
is enabled for safe public client-metadata fetches.

## Development

Use Node.js 24 and npm 9 or newer. The lockfile is version 3; older npm 6 may
misread it. Install the locked dependencies with `npm ci`.

For local OAuth testing, keep the Auth0 values in the ignored `.dev.vars` file.
Set `MCP_PUBLIC_URL` to the exact local origin `http://localhost:8787`, set the
three Auth0 values described above, and add
`http://localhost:8787/callback` to the Auth0 application's Allowed Callback
URLs. Do not put credentials in tracked files.

Start one local-only Worker over HTTP on loopback with:

```sh
npm run dev -- --local --ip 127.0.0.1 --port 8787 --local-protocol http
```

Configure an MCP client with the resource endpoint
`http://localhost:8787/mcp` and let it discover OAuth metadata and register
itself. The Worker advertises Dynamic Client Registration at
`/oauth/register` and supports Client ID Metadata Documents; do not invent a
client ID or manually open `/authorize` without a complete client authorization
request. The client supplies its registered callback URI, state, and S256 PKCE
challenge. Stop the local Worker with Ctrl+C in the same terminal.

If `/authorize` returns `Worker public URL is not configured`, inspect the
Wrangler terminal for the sanitized `MCP_PUBLIC_URL configuration diagnostic`.
It reports only whether the setting is nonempty and one fixed category:
`missing`, `malformed`, `canonical_origin_rejected`, or `unexpected`. Confirm
that Wrangler loaded `.dev.vars` from this project and that its origin exactly
matches the hostname used by the MCP client. The diagnostic never logs the URL
or OAuth credentials. A `421 Misdirected request` means the request hostname
does not match the configured public origin.

Run local automated checks with:

```sh
npm run type-check
npm test
```

The tests use Node.js 24's built-in test runner and the installed Workers OAuth
Provider package. They exercise registration, consent, state, PKCE, and token
handling with a mock Auth0 issuer. They do not contact a real Auth0 tenant or
verify deployment-specific callback configuration; only a real client login
can verify the complete configured OAuth flow.

## Demo data and priority score

The tools use illustrative sample data; live incident, resource, shelter, and
government-alert feeds are not connected. The deterministic demonstration
priority score remains:

```text
severity * 20 + min(peopleAffected, 200) / 10
```

It is not validated for real-world triage or dispatch.
