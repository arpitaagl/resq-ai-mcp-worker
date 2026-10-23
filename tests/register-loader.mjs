import { register } from "node:module";
import { pathToFileURL } from "node:url";

register("./cloudflare-loader.mjs", pathToFileURL("./tests/"));
