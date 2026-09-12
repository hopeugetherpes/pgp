# Standalone offline edition

`pgp.html` is a self-contained edition of PGP. Its interface, styles, favicon,
and OpenPGP implementation are embedded in that one file. It does not need a
server after download.

## Download safely

Download these release files from `https://pgp-offline.anatole.co/`:

- `pgp.html` — the standalone application
- `pgp.html.sha256` — its SHA-256 checksum
- `pgp.html.source.txt` — the exact source commit and artifact digest

A maintainer-signed release may additionally provide:

- `pgp.html.asc` — the maintainer's detached PGP signature
- `RELEASE-SIGNING-KEY.asc` — the public key used to verify that signature

Do not trust a signing key merely because it was downloaded beside the file it
signs. Confirm its full fingerprint through a separate trusted channel.

## Verify the checksum

Keep `pgp.html` and `pgp.html.sha256` in the same directory.

Linux:

```bash
sha256sum --check pgp.html.sha256
```

macOS:

```bash
shasum --algorithm 256 --check pgp.html.sha256
```

Windows PowerShell:

```powershell
$expected = (Get-Content .\pgp.html.sha256).Split()[0]
$actual = (Get-FileHash .\pgp.html -Algorithm SHA256).Hash.ToLower()
if ($actual -ne $expected) { throw "Checksum mismatch" }
"pgp.html: OK"
```

The result must say `pgp.html: OK`. A mismatch means the file is damaged or is
not the release described by the checksum; do not open it.

## Verify the maintainer signature (when provided)

After independently confirming the signing-key fingerprint:

```bash
gpg --import RELEASE-SIGNING-KEY.asc
gpg --verify pgp.html.asc pgp.html
```

The signature must be valid and its fingerprint must match the independently
confirmed maintainer fingerprint. A valid signature proves which key signed the
exact file; it does not by itself prove that the key belongs to the claimed
maintainer.

## Use it offline

1. Verify the checksum, plus the signature when provided, while the files are
   still easy to replace.
2. Disconnect from the network if your threat model requires it.
3. Open `pgp.html` directly in a trusted, up-to-date browser.
4. Generate keys or encrypt, decrypt, sign, and verify locally.
5. Clear the fields and close the tab when finished.

The standalone file enforces a Content Security Policy with
`default-src 'none'` and `connect-src 'none'`. The release build also fails if it
finds a network API, persistent browser-storage API, external resource, or Sites
host callback in the generated file.

The browser and operating system still matter. This application cannot protect
secrets from a compromised browser, extension, operating system, or device.

## Build and sign a release

Build from a clean, reviewed commit:

```bash
pnpm install --frozen-lockfile
pnpm run build:static
```

The build writes `dist/pgp.html`, its checksum, and its source-provenance record.
To sign with an existing local GPG key, use the key's complete fingerprint:

```bash
PGP_SIGNING_KEY=FULL_40_CHARACTER_FINGERPRINT pnpm run sign:standalone
```

The signing command creates `dist/pgp.html.asc`, verifies it immediately, and
exports only the public key to `dist/RELEASE-SIGNING-KEY.asc`. The private key
never enters the repository or build output.
