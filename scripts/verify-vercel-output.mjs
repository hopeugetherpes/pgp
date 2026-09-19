import { createHash } from "node:crypto"
import { readFile, readdir, stat } from "node:fs/promises"
import { dirname, resolve } from "node:path"
import { fileURLToPath } from "node:url"

const projectDirectory = resolve(dirname(fileURLToPath(import.meta.url)), "..")
const outputDirectory = resolve(projectDirectory, "dist")

function assert(condition, message) {
  if (!condition) throw new Error(message)
}

const config = JSON.parse(await readFile(resolve(projectDirectory, "vercel.json"), "utf8"))
const packageManifest = JSON.parse(await readFile(resolve(projectDirectory, "package.json"), "utf8"))
const readme = await readFile(resolve(projectDirectory, "README.md"), "utf8")
assert(config.framework === null, "Vercel must use the Other framework preset.")
assert(config.installCommand === "pnpm install --frozen-lockfile", "Unexpected Vercel install command.")
assert(config.buildCommand === "pnpm run build:vercel", "Unexpected Vercel build command.")
assert(config.outputDirectory === "dist", "Vercel must publish dist/.")
assert(config.cleanUrls === false, "Vercel must preserve the pgp.html filename.")
assert(config.git?.deploymentEnabled === true, "Automatic Git deployments must remain enabled.")
assert(
  readme.includes("https://vercel.com/new/clone?repository-url=https%3A%2F%2Fgithub.com%2Fhopeugetherpes%2Fpgp"),
  "The README Vercel button does not target hopeugetherpes/pgp.",
)

const installedPackages = {
  ...packageManifest.dependencies,
  ...packageManifest.devDependencies,
}
for (const forbiddenPackage of ["next", "drizzle-orm", "wrangler", "@cloudflare/vite-plugin"]) {
  assert(!(forbiddenPackage in installedPackages), `Unexpected server/platform package: ${forbiddenPackage}`)
}

const cspFor = (source) => config.headers
  ?.find((rule) => rule.source === source)
  ?.headers.find((header) => header.key === "Content-Security-Policy")
  ?.value
const hostedCsp = cspFor("/")
const standaloneCsp = cspFor("/pgp.html")
assert(hostedCsp?.includes("default-src 'none'"), "The hosted Vercel route must deny resources by default.")
assert(hostedCsp?.includes("connect-src 'none'"), "The hosted Vercel route must block network connections.")
assert(!hostedCsp?.includes("script-src 'unsafe-inline'"), "The hosted Vercel route must not allow inline scripts.")
assert(hostedCsp?.includes("frame-src 'none'"), "The hosted Vercel route must block frames.")
assert(standaloneCsp?.includes("connect-src 'none'"), "The standalone Vercel route must block network connections.")
assert(standaloneCsp?.includes("script-src 'unsafe-inline'"), "The standalone Vercel route must permit its embedded script.")

const commonHeaders = Object.fromEntries(
  (config.headers?.find((rule) => rule.source === "/(.*)")?.headers ?? [])
    .map(({ key, value }) => [key.toLowerCase(), value]),
)
assert(commonHeaders["referrer-policy"] === "no-referrer", "Vercel must suppress referrers.")
assert(commonHeaders["x-content-type-options"] === "nosniff", "Vercel must disable MIME sniffing.")
assert(commonHeaders["x-frame-options"] === "DENY", "Vercel must deny framing.")
assert(commonHeaders["cross-origin-resource-policy"] === "same-origin", "Vercel must isolate resources.")
assert(commonHeaders["cross-origin-opener-policy"] === "same-origin", "Vercel must isolate the browsing context.")
assert(commonHeaders["cross-origin-embedder-policy"] === "require-corp", "Vercel must require same-origin embedders.")

const requiredFiles = [
  "index.html",
  "favicon.svg",
  "assets/pgp.css",
  "assets/pgp.js",
  "pgp.html",
  "pgp.html.sha256",
  "pgp.html.source.txt",
]

for (const file of requiredFiles) {
  const details = await stat(resolve(outputDirectory, file))
  assert(details.isFile() && details.size > 0, `Missing or empty Vercel output: dist/${file}`)
}

const rootEntries = (await readdir(outputDirectory)).sort()
assert(
  JSON.stringify(rootEntries) === JSON.stringify(["assets", "favicon.svg", "index.html", "pgp.html", "pgp.html.sha256", "pgp.html.source.txt"]),
  `Unexpected files in dist/: ${rootEntries.join(", ")}`,
)
const assetEntries = (await readdir(resolve(outputDirectory, "assets"))).sort()
assert(
  JSON.stringify(assetEntries) === JSON.stringify(["pgp.css", "pgp.js"]),
  `Unexpected files in dist/assets/: ${assetEntries.join(", ")}`,
)

const indexHtml = await readFile(resolve(outputDirectory, "index.html"), "utf8")
for (const asset of ["./favicon.svg", "./assets/pgp.css", "./assets/pgp.js"]) {
  assert(indexHtml.includes(asset), `dist/index.html does not reference ${asset}.`)
}
assert(indexHtml.includes("connect-src 'none'"), "The hosted application is missing its network-blocking CSP.")

const standalone = await readFile(resolve(outputDirectory, "pgp.html"), "utf8")
const hostedScript = await readFile(resolve(outputDirectory, "assets/pgp.js"), "utf8")
const checksumFile = await readFile(resolve(outputDirectory, "pgp.html.sha256"), "utf8")
const checksumMatch = checksumFile.match(/^([0-9a-f]{64})  pgp\.html\n$/)
assert(checksumMatch, "The standalone checksum file has an invalid format.")
const actualChecksum = createHash("sha256").update(standalone).digest("hex")
assert(actualChecksum === checksumMatch[1], "The standalone HTML does not match its SHA-256 checksum.")

const forbiddenRuntimeTokens = [
  "fetch(",
  "XMLHttpRequest",
  "WebSocket",
  "EventSource",
  "sendBeacon",
  "localStorage",
  "sessionStorage",
  "indexedDB",
  "document.cookie",
  "serviceWorker",
  "modelContext",
  "registerTool",
]

for (const token of forbiddenRuntimeTokens) {
  assert(!standalone.includes(token), `The standalone HTML contains forbidden runtime capability: ${token}`)
  assert(!hostedScript.includes(token), `The hosted script contains forbidden runtime capability: ${token}`)
}

const provenance = await readFile(resolve(outputDirectory, "pgp.html.source.txt"), "utf8")
assert(/^Source commit: [0-9a-f]{40}$/m.test(provenance), "The standalone provenance has no complete source commit.")
assert(/^Source: https:\/\/github\.com\/[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+\/commit\/[0-9a-f]{40}$/m.test(provenance), "The standalone provenance has no valid GitHub source URL.")

console.log(`Verified Vercel static output (${requiredFiles.length} files, pgp.html SHA-256 ${actualChecksum}).`)
