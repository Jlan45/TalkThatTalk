import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import { mkdir, writeFile } from "node:fs/promises";

const version = "0.15.0";
const integrity = "DuB5JnoF+Vg3J0jBfhjYm1AIXwdqweozc2sc7TPlc26lVyuSOuCHdFrI3LNY3VF0x1Sleq85drgoVj7cehEzsQ==";
const url = `https://registry.npmjs.org/pi-antigravity/-/pi-antigravity-${version}.tgz`;
const response = await fetch(url, { signal: AbortSignal.timeout(25_000) });
if (!response.ok) {
  throw new Error(`pi-antigravity download failed with HTTP ${response.status}`);
}
const tarball = Buffer.from(await response.arrayBuffer());
if (createHash("sha512").update(tarball).digest("base64") !== integrity) {
  throw new Error("pi-antigravity package integrity mismatch");
}

const oauth = execFileSync("tar", ["-xOzf", "-", "package/src/auth/oauth.ts"], {
  input: tarball,
  encoding: "utf8",
});

function readClientDefault(name) {
  const declaration = oauth.match(new RegExp(`export const ${name}\\s*=([^;]+);`))?.[1];
  const encoded = declaration?.match(/atob\(([\s\S]+)\)/)?.[1];
  if (!encoded) throw new Error(`Missing ${name} in the published OAuth preset`);
  const fragments = Array.from(encoded.matchAll(/"([A-Za-z0-9+/=]+)"/g), ([, fragment]) => fragment);
  return Buffer.from(fragments.join(""), "base64").toString("utf8");
}

const clientId = readClientDefault("CLIENT_ID");
const clientSecret = readClientDefault("CLIENT_SECRET");
if (!/^[\w-]+\.apps\.googleusercontent\.com$/.test(clientId) || !/^GOCSPX-[\w-]+$/.test(clientSecret)) {
  throw new Error("Unexpected pi-antigravity desktop OAuth client format");
}

const target = new URL("../target/", import.meta.url);
await mkdir(target, { recursive: true });
await writeFile(new URL("antigravity-oauth", target), `${clientId}\n${clientSecret}\n`, { mode: 0o600 });
console.log(`Prepared desktop OAuth defaults from pi-antigravity ${version}`);
