import { createHash } from "node:crypto"
import { execFileSync } from "node:child_process"
import { readFile, writeFile } from "node:fs/promises"
import { dirname, resolve } from "node:path"
import { fileURLToPath } from "node:url"

const projectDirectory = resolve(dirname(fileURLToPath(import.meta.url)), "..")
const outputDirectory = resolve(projectDirectory, "dist")
const indexPath = resolve(outputDirectory, "index.html")
const standalonePath = resolve(outputDirectory, "pgp.html")
const checksumPath = `${standalonePath}.sha256`
const provenancePath = `${standalonePath}.source.txt`

function localGitCommit() {
  try {
    return execFileSync("git", ["rev-parse", "--verify", "HEAD"], {
      cwd: projectDirectory,
      encoding: "utf8",
      stdio: ["ignore", "pipe", "ignore"],
    })
  } catch {
    throw new Error(
      "No source commit is available. Build from Git or set PGP_SOURCE_COMMIT to a complete commit SHA.",
    )
  }
}

const sourceCommit = (
  process.env.PGP_SOURCE_COMMIT ||
  process.env.VERCEL_GIT_COMMIT_SHA ||
  localGitCommit()
).trim()

if (!/^[0-9a-f]{40}$/.test(sourceCommit)) {
  throw new Error("The source commit must be a complete lowercase 40-character Git SHA.")
}

const vercelRepository = [
  process.env.VERCEL_GIT_REPO_OWNER?.trim(),
  process.env.VERCEL_GIT_REPO_SLUG?.trim(),
]
const sourceRepository = vercelRepository.every((part) => part && /^[A-Za-z0-9_.-]+$/.test(part))
  ? vercelRepository.join("/")
  : "hopeugetherpes/pgp"

const offlinePolicy = [
  "default-src 'none'",
  "connect-src 'none'",
  "img-src data: blob:",
  "media-src data: blob:",
  "font-src data:",
  "style-src 'unsafe-inline' data:",
  "script-src 'unsafe-inline' 'wasm-unsafe-eval'",
  "worker-src blob:",
  "object-src 'none'",
  "base-uri 'none'",
  "form-action 'none'",
  "frame-src 'none'",
  "frame-ancestors 'none'",
  "manifest-src 'none'",
].join("; ")

function escapeAttribute(value) {
  return value
    .replaceAll("&", "&amp;")
    .replaceAll('"', "&quot;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
}

function escapeScript(value) {
  return value.replace(/<\/script/gi, "<\\/script")
}

function localOutputPath(value) {
  const clean = value.split(/[?#]/, 1)[0].replace(/^\.\//, "")
  if (!clean || clean.startsWith("/") || clean.includes("..")) {
    throw new Error(`Refusing to inline unexpected asset path: ${value}`)
  }
  const resolved = resolve(outputDirectory, clean)
  if (!resolved.startsWith(`${outputDirectory}/`)) {
    throw new Error(`Refusing to read outside the output directory: ${value}`)
  }
  return resolved
}

let html = await readFile(indexPath, "utf8")

html = html.replace(
  /<meta\s+http-equiv="Content-Security-Policy"\s+content="[^"]*"\s*\/?>/i,
  `<meta http-equiv="Content-Security-Policy" content="${escapeAttribute(offlinePolicy)}" />`,
)
html = html.replace("<html ", '<html data-pgp-offline="true" ')

for (const match of [...html.matchAll(/<link\b[^>]*rel="stylesheet"[^>]*href="([^"]+)"[^>]*>/gi)].reverse()) {
  const css = await readFile(localOutputPath(match[1]), "utf8")
  html = `${html.slice(0, match.index)}<style>${css}</style>${html.slice((match.index ?? 0) + match[0].length)}`
}

for (const match of [...html.matchAll(/<link\b[^>]*rel="icon"[^>]*href="([^"]+)"[^>]*>/gi)].reverse()) {
  const svg = await readFile(localOutputPath(match[1]), "utf8")
  const dataUrl = `data:image/svg+xml;base64,${Buffer.from(svg).toString("base64")}`
  html = html.replace(match[1], dataUrl)
}

for (const match of [...html.matchAll(/<script\b([^>]*)src="([^"]+)"([^>]*)><\/script>/gi)].reverse()) {
  const script = await readFile(localOutputPath(match[2]), "utf8")
  const attributes = `${match[1]}${match[3]}`.replace(/\s*crossorigin(?:="[^"]*")?/gi, "")
  const replacement = `<script${attributes}>${escapeScript(script)}</script>`
  html = `${html.slice(0, match.index)}${replacement}${html.slice((match.index ?? 0) + match[0].length)}`
}

if (/<(?:script|img|source|video|audio)\b[^>]*\bsrc="(?!data:|blob:)[^"]+"/i.test(html)) {
  throw new Error("Standalone app still contains an external source resource.")
}
if (/<link\b[^>]*\bhref="(?!data:|blob:|#)[^"]+"/i.test(html)) {
  throw new Error("Standalone app still contains an external link resource.")
}
if (!html.includes("connect-src 'none'")) {
  throw new Error("Standalone app is missing its network-blocking policy.")
}
if (!html.includes("data-pgp-offline")) {
  throw new Error("Standalone app is missing its offline-edition marker.")
}

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
  if (html.includes(token)) {
    throw new Error(`Standalone app contains forbidden runtime capability: ${token}`)
  }
}

await writeFile(standalonePath, html)
const checksum = createHash("sha256").update(html).digest("hex")
await writeFile(checksumPath, `${checksum}  pgp.html\n`)
await writeFile(
  provenancePath,
  [
    "PGP standalone release provenance",
    "",
    "Artifact: pgp.html",
    `SHA-256: ${checksum}`,
    `Source commit: ${sourceCommit}`,
    `Source: https://github.com/${sourceRepository}/commit/${sourceCommit}`,
    "",
  ].join("\n"),
)

console.log(`Created dist/pgp.html (${(Buffer.byteLength(html) / 1024 / 1024).toFixed(2)} MiB)`)
console.log(`SHA-256: ${checksum}`)
console.log(`Source commit: ${sourceCommit}`)
