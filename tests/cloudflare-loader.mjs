export async function resolve(specifier, context, nextResolve) {
	if (specifier === "cloudflare:workers") {
		return {
			url: "data:text/javascript,globalThis.Cloudflare%3D%7BcompatibilityFlags%3A%7Bglobal_fetch_strictly_public%3Atrue%7D%7D%3Bexport%20class%20WorkerEntrypoint%20%7B%7D",
			shortCircuit: true,
		};
	}
	if (specifier.startsWith(".") && !/\.[cm]?js$|\.ts$/.test(specifier)) {
		return nextResolve(`${specifier}.ts`, context);
	}
	return nextResolve(specifier, context);
}
