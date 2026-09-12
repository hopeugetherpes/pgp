<h1 align="center">🔑 PGP</h1>

<p align="center">
  <strong>OpenPGP encryption, signatures, and key management — entirely inside your browser.</strong>
</p>

<p align="center">
  <a href="https://pgp-offline.anatole.co"><strong>Open PGP</strong></a>
  ·
  <a href="dist/pgp.html"><strong>Download the standalone app</strong></a>
  ·
  <a href="OFFLINE.md"><strong>Offline verification guide</strong></a>
</p>

# **Private OpenPGP, Without the Black Box**

PGP is a privacy-focused OpenPGP web application for generating keys and protecting messages or attachments without sending sensitive material to a server. Encryption, decryption, signing, and verification all happen locally on your device.

## Purpose

PGP makes the essential OpenPGP workflows understandable and accessible from a modern browser. It uses the recipient's public key for encryption, the corresponding private key for decryption, the sender's private key for signing, and the sender's public key for verification.

| Operation | Key required | What it accomplishes |
| --- | --- | --- |
| **Encrypt** | Recipient's **public key** | Creates data only the matching private key can decrypt |
| **Decrypt** | Recipient's **private key** | Recovers the encrypted message or attachment |
| **Sign** | Sender's **private key** | Proves control of the signing key and detects alteration |
| **Verify** | Sender's **public key** | Checks the signature and displays the signing identity details |

> [!IMPORTANT]
> Share public keys freely. Never send anyone your private key or its passphrase.

**Key Features:**

- 🔑 **PGP Key Generation** — Create passphrase-protected public/private key pairs with a revocation certificate
- 🧬 **Modern or Compatible Keys** — Choose **Curve25519 (recommended)**, NIST P-256/P-384/P-521, or **RSA 4096 (legacy compatibility)**
- 🔐 **Message Encryption** — Encrypt text with the recipient's public key and optionally sign it
- 🔓 **Message Decryption** — Decrypt armored PGP messages and optionally require a valid sender signature
- ✍️ **Digital Signatures** — Create and verify cleartext signatures for messages
- 📎 **Attachment Protection** — Encrypt, decrypt, sign, and verify files locally
- 📨 **Email-Friendly Outputs** — Produce portable `.asc`, `.pgp`, and `.sig.asc` attachments
- 📦 **Streamed File Processing** — No application-imposed size cap; practical limits depend on the browser and available memory
- 💾 **Direct-to-Disk Output** — Supported Chromium browsers can stream large encrypted or decrypted results directly to disk
- 📴 **Standalone Offline Edition** — Run the complete application from one self-contained `pgp.html` file
- 🌐 **Local Processing** — No accounts, uploads, analytics, telemetry, APIs, or cryptographic backend
- 🎯 **Zero Knowledge** — There is no server-side component capable of receiving your keys, files, messages, or passphrases
- 📱 **Cross-Platform** — Works in modern desktop and mobile browsers
- 🆓 **[Open Source](https://github.com/hopeugetherpes/pgp)** — Fully auditable code released under the [CC0](LICENSE) public-domain dedication

## 📖 Usage

### Generate a Key Pair

1. Visit the [🔑 PGP web application](https://pgp-offline.anatole.co)
2. Open **Generate**
3. Enter the required email address and, optionally, a name to attach to the public key
4. Protect the private key with a passphrase of at least 12 characters
5. Choose **Curve25519 (recommended)**, a NIST curve, or **RSA 4096 (legacy compatibility)**
6. Click **Generate key pair**
7. Download the public key, private key, and revocation certificate

Keep the private key and its passphrase separate and secret. Share only the public `.asc` key. Store the revocation certificate somewhere safe so the key can be invalidated if the private key is lost or compromised.

### Encrypt a Message

1. Open **Encrypt**
2. Paste or load the recipient's public key
3. Enter or load the message
4. Optionally enable **Sign with my private key**
5. Click **Encrypt message**
6. Copy the armored result or download `encrypted-message.asc`

The private signing key is optional. It authenticates the sender; it is not used to encrypt the message.

### Decrypt a Message

1. Open **Decrypt**
2. Paste the encrypted PGP message or load its `.asc` attachment
3. Add the private key corresponding to the recipient public key
4. Enter the private-key passphrase when required
5. Optionally require verification with the sender's public key
6. Click **Decrypt message**

### Sign or Verify a Message

- **Sign:** Add the message, your private key, and its passphrase to create a cleartext signed `.asc` message.
- **Verify:** Add the signed message and the sender's public key. PGP checks the signature and displays the signing key ID and fingerprint.

A valid signature proves that the message was signed by the corresponding private key and was not subsequently altered. It does not prove the owner's real-world identity unless you independently verify the public-key fingerprint.

### Encrypt or Decrypt an Attachment

1. Open **Files**
2. Choose **Encrypt** or **Decrypt**
3. Select the attachment
4. Supply the recipient's public key for encryption or the matching private key for decryption
5. Optionally sign during encryption or require signature verification during decryption
6. Save the resulting `.pgp` file or restored attachment

File input is processed as a stream. When the browser exposes the File System Access API, output can also be written directly to disk instead of being accumulated in memory.

### Sign or Verify an Attachment

- **Sign:** Select the original attachment and your private key to create a detached `.sig.asc` signature.
- **Verify:** Select the unchanged original file, its `.sig.asc` signature, and the sender's public key.

The detached signature does not contain the original file. Send both the unchanged file and its signature.

## ⚠️ Limitations

### Key and Passphrase Recovery

There is no account, escrow system, recovery email, or “forgot passphrase” option. A lost private key or forgotten passphrase cannot be recovered by this project. This is intentional.

### Signatures and Identity

A valid signature confirms possession of a particular private key—not a person's legal identity. Compare the complete public-key fingerprint through a separate trusted channel before relying on it.

### File Size and Browser Memory

PGP sets no application-defined attachment size limit and always streams file input. Chromium browsers with direct-to-disk saving provide the best experience for very large files.

Browsers without the File System Access API buffer downloadable output in memory. Their practical maximum therefore depends on available RAM, browser limits, operating-system limits, and device stability. Mobile browsers and Safari may reach those limits earlier.

### Browser and Device Trust

Local processing protects data from a remote application server. It cannot protect secrets from a compromised browser, malicious extension, infected operating system, physical attacker, or untrusted device.

The hosted version must download its static HTML, CSS, and JavaScript before it can run. For a workflow with no continuing network dependency, verify and open the standalone edition after disconnecting.

## 🛡️ Security Architecture

PGP is designed around auditable, browser-side controls:

- **[OpenPGP.js](https://github.com/openpgpjs/openpgpjs)** — OpenPGP implementation used for every cryptographic operation
- **[OpenPGP](https://www.rfc-editor.org/rfc/rfc9580.html)** — interoperable message, key, encryption, and signature formats
- **Public-Key Encryption** — encryption requires the recipient's public key; private keys are reserved for decryption and signing
- **Protected Private Keys** — generated private keys are encrypted with the user-supplied passphrase
- **Signature Verification** — supports embedded message/file signatures, cleartext signatures, and detached file signatures
- **Ephemeral Handling** — keys, passphrases, messages, and file data remain in the current tab's memory until cleared or the tab closes
- **No Persistent Storage** — no `localStorage`, IndexedDB, cookies, accounts, analytics, or telemetry
- **No Application Network Calls** — the deployed Content Security Policy sets `connect-src 'none'`
- **Hardened Standalone Build** — `pgp.html` uses `default-src 'none'` and embeds its required interface, styles, and JavaScript
- **Release Verification** — the build emits a SHA-256 checksum and a source-provenance record alongside the standalone file

> [!NOTE]
> “Nothing leaves your device” describes application data and cryptographic operations. The hosted page itself is still downloaded from the web. The standalone edition can be downloaded once, verified, and then used with the network disconnected.

## Development

### Prerequisites

- Node.js 22
- pnpm 11

### Installation

```bash
git clone https://github.com/hopeugetherpes/pgp.git
cd pgp
pnpm install --frozen-lockfile
pnpm dev
```

### Building

```bash
pnpm run build:static
```

The production build is a static site written to `dist/`. It also creates the portable offline release:

- `dist/index.html` — static web application entry point
- `dist/assets/pgp.css` — production stylesheet
- `dist/assets/pgp.js` — browser application and bundled OpenPGP implementation
- `dist/pgp.html` — complete self-contained offline application
- `dist/pgp.html.sha256` — SHA-256 checksum for the standalone application
- `dist/pgp.html.source.txt` — exact source commit and artifact digest

To run the same build and output checks used by Vercel:

```bash
pnpm run build:vercel
```

The verification step rejects missing deployment files, an invalid standalone checksum, external runtime resources, application network APIs, persistent browser-storage APIs, and obsolete Sites callbacks.

See [OFFLINE.md](OFFLINE.md) for checksum verification, offline-use guidance, the threat model, and the optional maintainer-signing workflow.

## ▲ Deploy to Vercel

[![Deploy with Vercel](https://vercel.com/button)](https://vercel.com/new/clone?repository-url=https%3A%2F%2Fgithub.com%2Fhopeugetherpes%2Fpgp&project-name=pgp&repository-name=pgp)

PGP is configured for automatic deployment from GitHub:

1. In Vercel, choose **Add New → Project**
2. Import `https://github.com/hopeugetherpes/pgp`
3. Click **Deploy** without adding environment variables or changing the detected settings
4. Add `pgp-offline.anatole.co` under the project's **Domains** settings

The committed `vercel.json` selects the locked pnpm installation, verified static build, `dist/` output directory, and security headers. No server function, API, database, secret, or external runtime service is required.

With Vercel Git integration enabled, pushes to `main` deploy to production and pushes to other branches create preview deployments automatically.

## License

Released into the public domain under the [CC0 1.0 Universal](LICENSE) dedication.

---
