import { spawnSync } from "node:child_process"
import { readFile, writeFile } from "node:fs/promises"
import { dirname, resolve } from "node:path"
import { fileURLToPath } from "node:url"

const projectDirectory = resolve(dirname(fileURLToPath(import.meta.url)), "..")
const standalonePath = resolve(projectDirectory, "dist/pgp.html")
const signaturePath = `${standalonePath}.asc`
const publicKeyPath = resolve(projectDirectory, "dist/RELEASE-SIGNING-KEY.asc")
const signingKey = process.env.PGP_SIGNING_KEY?.trim()

if (!signingKey) {
  throw new Error(
    "Set PGP_SIGNING_KEY to the full fingerprint of your existing release-signing key.",
  )
}

await readFile(standalonePath)

function runGpg(arguments_, options = {}) {
  const result = spawnSync("gpg", arguments_, {
    cwd: projectDirectory,
    stdio: options.capture ? ["ignore", "pipe", "inherit"] : "inherit",
  })
  if (result.error) throw result.error
  if (result.status !== 0) {
    throw new Error(`gpg exited with status ${result.status}`)
  }
  return result.stdout
}

runGpg([
  "--yes",
  "--armor",
  "--local-user",
  signingKey,
  "--output",
  signaturePath,
  "--detach-sign",
  standalonePath,
])

runGpg(["--verify", signaturePath, standalonePath])

const publicKey = runGpg(["--armor", "--export", signingKey], { capture: true })
if (!publicKey?.length) throw new Error("The signing key could not be exported.")
await writeFile(publicKeyPath, publicKey)

console.log(`Created ${signaturePath}`)
console.log(`Exported the public verification key to ${publicKeyPath}`)
