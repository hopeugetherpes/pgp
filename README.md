# PGP

A privacy-first OpenPGP workbench that runs entirely in the browser.

## What it does

- Generates passphrase-protected public/private PGP key pairs
- Encrypts text with a recipient's public key and can sign it with the sender's private key
- Decrypts armored PGP messages and can verify the sender with their public key
- Creates and verifies cleartext PGP signatures
- Streams file encryption, decryption, signing, and verification without an app-defined size cap
- Creates email-friendly `.asc`, `.sig.asc`, and `.pgp` attachments
- Produces a self-contained `pgp.html` edition for fully offline use

Large file input is always streamed. Browsers that expose the File System Access
API can also stream encrypted and decrypted output directly to disk. Other
browsers buffer downloadable output in memory, so their practical maximum depends
on available browser memory even though PGP sets no fixed file-size limit.

## Privacy model

Cryptographic operations run locally with OpenPGP.js. The app has no accounts,
analytics, telemetry, persistent browser storage, or API calls. A Content Security
Policy sets `connect-src 'none'`, blocking application network connections.

The hosted page necessarily downloads its static HTML, CSS, and JavaScript once.
For a workflow with no network dependency at all, download `pgp.html`, close
the hosted tab, disconnect from the network, and open the downloaded file locally.

Keys and passphrases remain in the current tab's memory until cleared or the tab is
closed. This does not protect against a compromised browser, extension, operating
system, or device.

## Local build

Requirements: Node.js 22+ and pnpm.

```bash
pnpm install --frozen-lockfile
pnpm run build:static
```

The deployable static site is written to `dist/`. The standalone edition and its
integrity files are:

- `dist/pgp.html`
- `dist/pgp.html.sha256`
- `dist/pgp.html.source.txt`
- `dist/pgp.html.asc` after the maintainer signs it
- `dist/RELEASE-SIGNING-KEY.asc` containing only the public verification key

See [OFFLINE.md](OFFLINE.md) for checksum and signature verification, safe
offline-use instructions, threat-model limits, and the maintainer signing flow.

## Deploy automatically on Vercel

[![Deploy with Vercel](https://vercel.com/button)](https://vercel.com/new/clone?repository-url=https%3A%2F%2Fgithub.com%2Fhopeugetherpes%2Fpgp&project-name=pgp&repository-name=pgp)

Import the GitHub repository once with the button above. No environment variables,
APIs, server functions, or persistent storage are required. The committed
`vercel.json` makes Vercel install the locked pnpm dependencies, run the verified
static build, and publish `dist/`.

With Vercel's Git integration enabled, pushes to `main` deploy to production and
pushes to other branches create preview deployments automatically. Add
`pgp.anatole.co` under the Vercel project's Domains settings after the first
deployment; domain ownership and DNS configuration are intentionally not stored
in this public repository.

The Vercel build uses the deployment's Git commit and repository metadata in
`pgp.html.source.txt`, so the downloadable standalone file keeps auditable source
provenance on production and preview deployments.

## License

Released into the public domain under [CC0 1.0](LICENSE).
