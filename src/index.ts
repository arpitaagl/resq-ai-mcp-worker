import { McpServer } from "@modelcontextprotocol/server";
import { createMcpHandler } from "agents/mcp/server";
import { OAuthProvider } from "@cloudflare/workers-oauth-provider";
import {
	createOAuthHandlers,
	getCanonicalOrigin,
	isCanonicalOriginRequest,
	publicUrlDiagnosticCategory,
	type RuntimeEnv,
} from "./oauth-handlers";
import { z } from "zod";

type Incident = {
	id: string;
	type: string;
	location: string;
	severity: number;
	peopleAffected: number;
	status: "active" | "resolved";
	description: string;
};

const SAMPLE_INCIDENTS: Incident[] = [
	{
		id: "DEMO-001",
		type: "Flood",
		location: "Sample District A",
		severity: 5,
		peopleAffected: 120,
		status: "active",
		description: "Illustrative flood incident for testing only.",
	},
	{
		id: "DEMO-002",
		type: "Earthquake",
		location: "Sample District B",
		severity: 4,
		peopleAffected: 75,
		status: "active",
		description: "Illustrative earthquake incident for testing only.",
	},
	{
		id: "DEMO-003",
		type: "Storm",
		location: "Sample District C",
		severity: 2,
		peopleAffected: 20,
		status: "resolved",
		description: "Illustrative resolved storm incident for testing only.",
	},
];

function calculatePriority(incident: Incident): number {
	// Deterministic demonstration score; not a real-world dispatch decision.
	return incident.severity * 20 + Math.min(incident.peopleAffected, 200) / 10;
}

function textResult(value: unknown) {
	return {
		content: [{ type: "text" as const, text: JSON.stringify(value, null, 2) }],
	};
}

function createServer() {
	const server = new McpServer({
		name: "ResQ-AI Read-Only Demo",
		version: "1.0.0",
	});

	server.registerTool(
		"list_incidents",
		{
			description: "List illustrative demo incidents. These are not live emergency reports.",
			inputSchema: z.object({
				status: z.enum(["active", "resolved", "all"]).default("active"),
				limit: z.number().int().min(1).max(50).default(10),
			}),
		},
		async ({ status, limit }) => {
			const incidents = SAMPLE_INCIDENTS.filter(
				(incident) => status === "all" || incident.status === status,
			)
				.sort((a, b) => calculatePriority(b) - calculatePriority(a))
				.slice(0, limit)
				.map((incident) => ({
					...incident,
					demoData: true,
					priorityScore: calculatePriority(incident),
				}));

			return textResult({
				source: "SAMPLE_DATA_NOT_LIVE",
				warning: "Do not use this demo data to make emergency response decisions.",
				count: incidents.length,
				incidents,
			});
		},
	);

	server.registerTool(
		"get_incident_details",
		{
			description: "Get details for one illustrative demo incident ID.",
			inputSchema: z.object({ incident_id: z.string().min(1).max(100) }),
		},
		async ({ incident_id }) => {
			const incident = SAMPLE_INCIDENTS.find(
				(item) => item.id.toLowerCase() === incident_id.toLowerCase(),
			);

			if (!incident) {
				return textResult({
					found: false,
					message: "No matching demo incident was found.",
					source: "SAMPLE_DATA_NOT_LIVE",
				});
			}

			return textResult({
				found: true,
				source: "SAMPLE_DATA_NOT_LIVE",
				warning: "This is illustrative data, not a verified emergency report.",
				incident,
				priorityScore: calculatePriority(incident),
			});
		},
	);

	server.registerTool(
		"explain_priority",
		{
			description:
				"Explain the deterministic demonstration priority score for a demo incident.",
			inputSchema: z.object({ incident_id: z.string().min(1).max(100) }),
		},
		async ({ incident_id }) => {
			const incident = SAMPLE_INCIDENTS.find(
				(item) => item.id.toLowerCase() === incident_id.toLowerCase(),
			);

			if (!incident) {
				return textResult({
					found: false,
					message: "No matching demo incident was found.",
					source: "SAMPLE_DATA_NOT_LIVE",
				});
			}

			return textResult({
				source: "SAMPLE_DATA_NOT_LIVE",
				incidentId: incident.id,
				scoreFormula: "severity * 20 + min(peopleAffected, 200) / 10",
				severity: incident.severity,
				peopleAffected: incident.peopleAffected,
				priorityScore: calculatePriority(incident),
				warning:
					"This demonstration score is not validated for real-world triage or dispatch.",
			});
		},
	);

	server.registerTool(
		"get_resource_status",
		{
			description:
				"Return an explicitly unavailable resource-status demo response. No live resource inventory is connected.",
			inputSchema: z.object({}),
		},
		async () =>
			textResult({
				source: "NO_LIVE_RESOURCE_CONNECTION",
				verifiedAvailableResources: null,
				message:
					"Live resource availability is not connected or verified. Contact the relevant emergency services or authorized operations team to confirm availability.",
				demoMode: true,
			}),
	);

	server.registerTool(
		"find_shelters",
		{
			description:
				"Explain shelter-data limitations. No real shelter inventory or capacity is connected.",
			inputSchema: z.object({
				minimum_spaces: z.number().int().min(0).default(0),
			}),
		},
		async ({ minimum_spaces }) =>
			textResult({
				source: "NO_LIVE_SHELTER_CONNECTION",
				requestedMinimumSpaces: minimum_spaces,
				shelters: [],
				verifiedAvailableShelters: null,
				message:
					"No shelter inventory or capacity has been verified by this Worker. Do not interpret the empty list as proof that no shelters exist. Confirm with official local authorities.",
			}),
	);

	server.registerTool(
		"generate_incident_brief",
		{
			description: "Generate a concise incident brief from illustrative demo incidents only.",
			inputSchema: z.object({}),
		},
		async () => {
			const active = SAMPLE_INCIDENTS.filter((incident) => incident.status === "active").sort(
				(a, b) => calculatePriority(b) - calculatePriority(a),
			);

			return textResult({
				source: "SAMPLE_DATA_NOT_LIVE",
				title: "ResQ-AI Demo Incident Brief",
				activeDemoIncidentCount: active.length,
				incidents: active.map((incident) => ({
					id: incident.id,
					type: incident.type,
					location: incident.location,
					priorityScore: calculatePriority(incident),
				})),
				warning: "This is a demonstration summary, not an operational situation report.",
			});
		},
	);

	server.registerTool(
		"get_live_government_alerts",
		{
			description:
				"Report that live government alerts are not yet connected; does not fabricate alerts.",
			inputSchema: z.object({
				state: z.string().max(100).default(""),
				district: z.string().max(100).default(""),
			}),
		},
		async ({ state, district }) =>
			textResult({
				source: "NO_LIVE_ALERT_FEED_CONNECTED",
				state: state || null,
				district: district || null,
				alerts: [],
				liveDataConnected: false,
				message:
					"Live government alert feeds are not connected in this Worker version. Check official government and meteorological sources for current warnings.",
			}),
	);

	return server;
}

const mcpHandler = createMcpHandler(createServer);
const { defaultHandler, apiHandler } = createOAuthHandlers(mcpHandler);

export default {
	fetch(request: Request, env: RuntimeEnv, ctx: ExecutionContext) {
		let canonicalOrigin: URL;
		try {
			canonicalOrigin = getCanonicalOrigin(env.MCP_PUBLIC_URL);
		} catch (error) {
			console.error("MCP_PUBLIC_URL configuration diagnostic", {
				configured: typeof env.MCP_PUBLIC_URL === "string" && env.MCP_PUBLIC_URL.length > 0,
				category: publicUrlDiagnosticCategory(error),
			});
			return new Response("Worker public URL is not configured.", { status: 500 });
		}

		if (!isCanonicalOriginRequest(request, canonicalOrigin)) {
			return new Response("Misdirected request.", { status: 421 });
		}

		const provider = new OAuthProvider<RuntimeEnv>({
			apiRoute: "/mcp",
			apiHandler,
			defaultHandler,
			authorizeEndpoint: "/authorize",
			tokenEndpoint: "/oauth/token",
			clientRegistrationEndpoint: "/oauth/register",
			clientIdMetadataDocumentEnabled: true,
			scopesSupported: ["mcp:read"],
			requiredScopes: ["mcp:read"],
			resourceMetadata: {
				resource: new URL("/mcp", canonicalOrigin).href,
				authorization_servers: [canonicalOrigin.origin],
				resource_name: "ResQ-AI MCP Worker",
			},
			refreshTokenTTL: 0,
		});
		return provider.fetch(request, env, ctx);
	},
} satisfies ExportedHandler<RuntimeEnv>;
