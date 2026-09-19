# Verify and use the offline edition

The standalone `pgp.html` file contains the interface, styles, OpenPGP implementation, and application code in one document. It does not need a server and its Content Security Policy blocks network connections.

## Download from GitHub

Download both files from the same source revision:

- [`dist/pgp.html`](dist/pgp.html)
- [`dist/pgp.html.sha256`](dist/pgp.html.sha256)

For a stronger check, inspect [`dist/pgp.html.source.txt`](dist/pgp.html.source.txt) and confirm that its source commit is the revision you intended to trust.

## Verify on macOS or Linux

Open a terminal in the directory containing both downloads, then run:

```bash
shasum -a 256 -c pgp.html.sha256
```

Linux systems with GNU coreutils can also use:

```bash
sha256sum -c pgp.html.sha256
```

The result must say `pgp.html: OK`.

## Verify on Windows PowerShell

Run:

```powershell
$expected = (Get-Content .\pgp.html.sha256).Split(' ')[0].ToLower()
$actual = (Get-FileHash .\pgp.html -Algorithm SHA256).Hash.ToLower()
if ($actual -ne $expected) { throw "Checksum mismatch" }
"pgp.html: OK"
```

## Important trust limitation

A checksum detects accidental corruption and confirms that two files match. It does not create trust when the HTML and checksum were obtained from the same compromised source. Compare against the copy committed on GitHub, a signed release when available, or a digest received through an independent trusted channel.

After verification, disconnect from the network if your threat model requires it and open `pgp.html` in a modern browser. The application does not persist keys or messages, but browser JavaScript cannot guarantee forensic memory erasure. Clear sensitive fields, close the tab, and fully quit the browser when finished.
