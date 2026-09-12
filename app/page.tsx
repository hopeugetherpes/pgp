"use client"

import { type DragEvent, useState, useSyncExternalStore } from "react"
import * as openpgp from "openpgp"
import {
  BadgeCheck,
  Check,
  Clipboard,
  Download,
  Eye,
  EyeOff,
  Files,
  FileKey,
  FileUp,
  KeyRound,
  LoaderCircle,
  LockKeyhole,
  Mail,
  PenLine,
  ShieldCheck,
  Trash2,
  UnlockKeyhole,
  Upload,
} from "lucide-react"
import { toast } from "sonner"

import { Button } from "@/components/ui/button"
import { Checkbox } from "@/components/ui/checkbox"
import { Input } from "@/components/ui/input"
import { Label } from "@/components/ui/label"
import { Progress } from "@/components/ui/progress"
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select"
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs"
import { Textarea } from "@/components/ui/textarea"
import { Toaster } from "@/components/ui/sonner"

type Workspace = "generate" | "encrypt" | "decrypt" | "sign" | "files"
type GeneratedKeys = {
  publicKey: string
  privateKey: string
  revocationCertificate: string
  fingerprint: string
  fileStem: string
}

type SignatureSummary = {
  fingerprint: string
  keyIds: string
}

type LocalWritableFile = {
  write(data: Uint8Array | Blob | string): Promise<void>
  close(): Promise<void>
  abort(reason?: unknown): Promise<void>
}

type LocalFileHandle = {
  createWritable(): Promise<LocalWritableFile>
}

type SaveFilePickerWindow = Window & {
  showSaveFilePicker?: (options: { suggestedName: string }) => Promise<LocalFileHandle>
}

type BinaryOutput = Uint8Array | ReadableStream<Uint8Array>
type SignatureCheck = {
  verified: Promise<true>
  keyID: { toHex(): string }
}

const keyFileTypes = ".asc,.key,.pgp,.gpg,.txt,text/plain,application/pgp-keys"
const messageFileTypes = ".asc,.pgp,.gpg,.txt,text/plain,application/pgp-encrypted"
const signatureFileTypes = ".asc,.sig,.txt,text/plain,application/pgp-signature"

function GitHubOutline() {
  return (
    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
      <path d="M15 22v-4a4.8 4.8 0 0 0-1-3.5c3.28 0 6.72-1.6 6.72-7A5.4 5.4 0 0 0 20 4.1 5 5 0 0 0 19.91 1S18.73.65 16 2.48a13.38 13.38 0 0 0-7 0C6.27.65 5.09 1 5.09 1A5 5 0 0 0 5 4.1a5.4 5.4 0 0 0-.72 3.4c0 5.42 3.44 7 6.72 7a4.8 4.8 0 0 0-1 3.5v4" />
      <path d="M9 18c-4.51 2-5-2-7-2" />
    </svg>
  )
}

function errorMessage(error: unknown) {
  return error instanceof Error ? error.message : "An unexpected cryptographic error occurred."
}

function safeFileStem(value: string) {
  const normalized = value
    .trim()
    .toLowerCase()
    .replace(/[^a-z0-9._-]+/g, "-")
    .replace(/^-+|-+$/g, "")
  return normalized || "pgp-key"
}

function safeOutputFilename(value: string, fallback: string) {
  const cleaned = value.replaceAll("\\", "/").split("/").pop()?.trim()
  return cleaned && cleaned !== "." && cleaned !== ".." ? cleaned : fallback
}

function encryptedFilename(filename: string) {
  return `${safeOutputFilename(filename, "attachment")}.pgp`
}

function decryptedFilename(filename: string) {
  const cleaned = safeOutputFilename(filename, "decrypted-attachment")
  return cleaned.replace(/\.(?:pgp|gpg|asc)$/i, "") || "decrypted-attachment"
}

function formatBytes(bytes: number) {
  if (bytes === 0) return "0 B"
  const units = ["B", "KB", "MB", "GB", "TB"]
  const exponent = Math.min(Math.floor(Math.log(bytes) / Math.log(1024)), units.length - 1)
  const value = bytes / 1024 ** exponent
  return `${value >= 10 || exponent === 0 ? value.toFixed(0) : value.toFixed(1)} ${units[exponent]}`
}

function groupedFingerprint(key: openpgp.PublicKey) {
  return key.getFingerprint().toUpperCase().match(/.{1,4}/g)?.join(" ") ?? key.getFingerprint().toUpperCase()
}

async function readPublicKey(armoredKey: string) {
  const key = await openpgp.readKey({ armoredKey: armoredKey.trim() })
  if (key.isPrivate()) throw new Error("Use a public key, not a private key.")
  return key
}

async function unlockPrivateKey(armoredKey: string, passphrase: string) {
  let key = await openpgp.readPrivateKey({ armoredKey: armoredKey.trim() })
  if (!key.isDecrypted()) {
    if (!passphrase) throw new Error("Enter the passphrase that protects this private key.")
    key = await openpgp.decryptKey({ privateKey: key, passphrase })
  }
  return key
}

async function verifySignatureChecks(signatures: SignatureCheck[]) {
  if (!signatures.length) throw new Error("No PGP signature was found.")
  await Promise.all(signatures.map(({ verified }) => verified))
  return [...new Set(signatures.map(({ keyID }) => keyID.toHex().toUpperCase()))].join(", ")
}

function isReadableStream(value: BinaryOutput): value is ReadableStream<Uint8Array> {
  return typeof (value as ReadableStream<Uint8Array>)?.getReader === "function"
}

function trackedFileStream(file: File, onProgress: (progress: number) => void) {
  const reader = file.stream().getReader()
  let processed = 0
  let lastUpdate = 0

  return new ReadableStream<Uint8Array>({
    async pull(controller) {
      const { done, value } = await reader.read()
      if (done) {
        onProgress(100)
        controller.close()
        return
      }
      processed += value.byteLength
      const now = performance.now()
      if (now - lastUpdate > 120 || processed >= file.size) {
        onProgress(file.size ? Math.min(100, (processed / file.size) * 100) : 100)
        lastUpdate = now
      }
      controller.enqueue(value)
    },
    cancel(reason) {
      return reader.cancel(reason)
    },
  })
}

function decodeUtf8Stream(stream: ReadableStream<Uint8Array>) {
  const decoder = new TextDecoder()
  return stream.pipeThrough(
    new TransformStream<Uint8Array, string>({
      transform(chunk, controller) {
        const text = decoder.decode(chunk, { stream: true })
        if (text) controller.enqueue(text)
      },
      flush(controller) {
        const text = decoder.decode()
        if (text) controller.enqueue(text)
      },
    }),
  )
}

async function readFileMessage(file: File, onProgress: (progress: number) => void) {
  const prefix = await file.slice(0, 96).text()
  const binaryStream = trackedFileStream(file, onProgress)
  if (prefix.replace(/^\uFEFF/, "").startsWith("-----BEGIN PGP MESSAGE-----")) {
    return openpgp.readMessage({ armoredMessage: decodeUtf8Stream(binaryStream) })
  }
  return openpgp.readMessage({ binaryMessage: binaryStream })
}

async function collectText(value: string | ReadableStream<string>) {
  if (typeof value === "string") return value
  const reader = value.getReader()
  let output = ""
  while (true) {
    const { done, value: chunk } = await reader.read()
    if (done) return output
    output += chunk
  }
}

async function consumeBinary(value: Uint8Array | ReadableStream<Uint8Array>) {
  if (!isReadableStream(value)) return
  const reader = value.getReader()
  while (!(await reader.read()).done) {
    // Consuming the stream is what completes detached-signature verification.
  }
}

function isCancelled(error: unknown) {
  return error instanceof DOMException && error.name === "AbortError"
}

async function requestOutputHandle(suggestedName: string) {
  const picker = (window as SaveFilePickerWindow).showSaveFilePicker
  if (!picker) return null
  return picker({ suggestedName })
}

async function chooseOutputHandle(suggestedName: string) {
  try {
    return await requestOutputHandle(suggestedName)
  } catch (error) {
    if (isCancelled(error)) throw error
    toast.warning("Direct-to-disk saving is unavailable; using the browser download buffer instead.")
    return null
  }
}

function downloadBlob(blob: Blob, filename: string) {
  const url = URL.createObjectURL(blob)
  const anchor = document.createElement("a")
  anchor.href = url
  anchor.download = filename
  document.body.appendChild(anchor)
  anchor.click()
  anchor.remove()
  window.setTimeout(() => URL.revokeObjectURL(url), 0)
}

async function writeBinaryOutput({
  output,
  filename,
  type,
  handle,
  beforeCommit,
}: {
  output: BinaryOutput
  filename: string
  type: string
  handle: LocalFileHandle | null
  beforeCommit?: () => Promise<void>
}) {
  if (handle) {
    const writable = await handle.createWritable()
    try {
      if (isReadableStream(output)) {
        const reader = output.getReader()
        while (true) {
          const { done, value } = await reader.read()
          if (done) break
          await writable.write(value)
        }
      } else {
        await writable.write(output)
      }
      await beforeCommit?.()
      await writable.close()
      return "streamed" as const
    } catch (error) {
      await writable.abort(error).catch(() => undefined)
      throw error
    }
  }

  let blob: Blob
  if (isReadableStream(output)) {
    blob = new Blob([await new Response(output).blob()], { type })
  } else {
    const bytes = new Uint8Array(new ArrayBuffer(output.byteLength))
    bytes.set(output)
    blob = new Blob([bytes], { type })
  }
  await beforeCommit?.()
  downloadBlob(blob, filename)
  return "buffered" as const
}

function downloadText(contents: string, filename: string, type = "text/plain;charset=utf-8") {
  const blob = new Blob([contents], { type })
  downloadBlob(blob, filename)
}

async function copyText(contents: string, label: string) {
  await navigator.clipboard.writeText(contents)
  toast.success(`${label} copied`)
}

function ImportFile({
  id,
  label,
  accept,
  onLoad,
}: {
  id: string
  label: string
  accept: string
  onLoad: (contents: string, filename: string) => void
}) {
  const [filename, setFilename] = useState("")

  return (
    <div className="flex flex-wrap items-center gap-2">
      <Input
        id={id}
        type="file"
        accept={accept}
        className="sr-only"
        onChange={async (event) => {
          const file = event.currentTarget.files?.[0]
          if (!file) return
          try {
            const contents = await file.text()
            if (!contents.trim()) throw new Error("The selected file is empty.")
            setFilename(file.name)
            onLoad(contents, file.name)
            toast.success(`${file.name} loaded locally`)
          } catch (error) {
            toast.error(errorMessage(error))
          } finally {
            event.currentTarget.value = ""
          }
        }}
      />
      <Button asChild variant="outline" size="sm" className="cursor-pointer">
        <label htmlFor={id}>
          <Upload aria-hidden="true" />
          {label}
        </label>
      </Button>
      {filename ? <span className="max-w-64 truncate text-sm text-muted-foreground">{filename}</span> : null}
    </div>
  )
}

function BinaryFilePicker({
  id,
  label,
  file,
  accept,
  onSelect,
}: {
  id: string
  label: string
  file: File | null
  accept?: string
  onSelect: (file: File | null) => void
}) {
  const [dragging, setDragging] = useState(false)

  function keepDropLocal(event: DragEvent<HTMLDivElement>) {
    event.preventDefault()
    event.stopPropagation()
  }

  return (
    <div
      className={`file-picker${dragging ? " is-dragging" : ""}`}
      onDragEnter={(event) => {
        keepDropLocal(event)
        setDragging(true)
      }}
      onDragOver={keepDropLocal}
      onDragLeave={(event) => {
        keepDropLocal(event)
        setDragging(false)
      }}
      onDrop={(event) => {
        keepDropLocal(event)
        setDragging(false)
        onSelect(event.dataTransfer.files?.[0] ?? null)
      }}
    >
      <Input
        id={id}
        type="file"
        accept={accept}
        className="sr-only"
        onChange={(event) => {
          onSelect(event.currentTarget.files?.[0] ?? null)
          event.currentTarget.value = ""
        }}
      />
      <label htmlFor={id} className="file-picker-label">
        <span className="file-picker-icon" aria-hidden="true"><FileUp /></span>
        <span>
          <strong>{file ? file.name : "Drag & Drop or Browse file"}</strong>
          <small>{file ? `${formatBytes(file.size)} · read locally as a stream` : label}</small>
        </span>
      </label>
      {file ? (
        <Button type="button" variant="ghost" size="sm" onClick={() => onSelect(null)}>
          <Trash2 aria-hidden="true" /> Remove
        </Button>
      ) : null}
    </div>
  )
}

function OperationProgress({ progress, label }: { progress: number; label: string }) {
  return (
    <div className="progress-block" aria-live="polite">
      <div className="progress-label">
        <span>{progress > 0 ? label : "Preparing cryptography…"}</span>
        <span>{Math.round(progress)}%</span>
      </div>
      <Progress value={progress} aria-label={`${label}: ${Math.round(progress)}%`} />
    </div>
  )
}

function VerificationBanner({ summary, title = "Signature verified" }: { summary: SignatureSummary; title?: string }) {
  return (
    <div className="verification-banner" role="status">
      <BadgeCheck aria-hidden="true" />
      <div>
        <strong>{title}</strong>
        <span>Signing key ID: {summary.keyIds}</span>
        <code>{summary.fingerprint}</code>
      </div>
    </div>
  )
}

function StreamingNote() {
  const directSave = useSyncExternalStore(
    () => () => undefined,
    () => "showSaveFilePicker" in window,
    () => false,
  )

  return (
    <div className="streaming-note">
      <ShieldCheck aria-hidden="true" />
      <div>
        <strong>No app-defined file-size limit</strong>
        <span>
          Files are processed as streams. {directSave
            ? "This browser can also write results directly to disk, keeping memory use bounded."
            : "This browser buffers downloaded results in memory; for very large files, use a Chromium browser with direct-to-disk saving."}
        </span>
      </div>
    </div>
  )
}

function SecretInput({
  id,
  value,
  onChange,
  placeholder,
}: {
  id: string
  value: string
  onChange: (value: string) => void
  placeholder: string
}) {
  const [visible, setVisible] = useState(false)

  return (
    <div className="relative">
      <Input
        id={id}
        type={visible ? "text" : "password"}
        value={value}
        onChange={(event) => onChange(event.target.value)}
        placeholder={placeholder}
        autoComplete="new-password"
        className="h-11 pr-12"
      />
      <Button
        type="button"
        variant="ghost"
        size="icon-sm"
        className="absolute right-2 top-1/2 -translate-y-1/2"
        onClick={() => setVisible((current) => !current)}
        aria-label={visible ? "Hide passphrase" : "Show passphrase"}
      >
        {visible ? <EyeOff aria-hidden="true" /> : <Eye aria-hidden="true" />}
      </Button>
    </div>
  )
}

function ResultBlock({
  title,
  value,
  filename,
  warning,
  type = "application/pgp-encrypted;charset=utf-8",
}: {
  title: string
  value: string
  filename: string
  warning?: string
  type?: string
}) {
  return (
    <section className="result-block" aria-live="polite">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div>
          <h3 className="text-base font-semibold">{title}</h3>
          {warning ? <p className="mt-1 text-sm text-amber-700">{warning}</p> : null}
        </div>
        <div className="flex gap-2">
          <Button type="button" variant="outline" size="sm" onClick={() => copyText(value, title)}>
            <Clipboard aria-hidden="true" />
            Copy
          </Button>
          <Button
            type="button"
            variant="outline"
            size="sm"
            onClick={() => downloadText(value, filename, type)}
          >
            <Download aria-hidden="true" />
            Download
          </Button>
        </div>
      </div>
      <Textarea value={value} readOnly spellCheck={false} className="code-field mt-3 min-h-48" />
    </section>
  )
}

function GenerateWorkspace() {
  const [name, setName] = useState("")
  const [email, setEmail] = useState("")
  const [passphrase, setPassphrase] = useState("")
  const [algorithm, setAlgorithm] = useState("curve25519Legacy")
  const [isWorking, setIsWorking] = useState(false)
  const [keys, setKeys] = useState<GeneratedKeys | null>(null)

  async function generate(event: React.FormEvent) {
    event.preventDefault()
    if (!email.trim()) {
      toast.error("Enter the email address to identify this key.")
      return
    }
    if (passphrase.length < 12) {
      toast.error("Use a passphrase of at least 12 characters.")
      return
    }

    setIsWorking(true)
    try {
      const userID = name.trim() ? { name: name.trim(), email: email.trim() } : { email: email.trim() }
      const generated =
        algorithm === "rsa4096"
          ? await openpgp.generateKey({
              type: "rsa",
              rsaBits: 4096,
              userIDs: [userID],
              passphrase,
              format: "armored",
            })
          : await openpgp.generateKey({
              type: "ecc",
              curve: algorithm as "curve25519Legacy" | "nistP256" | "nistP384" | "nistP521",
              userIDs: [userID],
              passphrase,
              format: "armored",
            })
      const publicKeyObject = await openpgp.readKey({ armoredKey: generated.publicKey })
      setKeys({
        publicKey: generated.publicKey,
        privateKey: generated.privateKey,
        revocationCertificate: generated.revocationCertificate,
        fingerprint: publicKeyObject.getFingerprint().toUpperCase().match(/.{1,4}/g)?.join(" ") ?? "",
        fileStem: safeFileStem(email),
      })
      toast.success("PGP key pair generated entirely in this browser")
    } catch (error) {
      toast.error(`Key generation failed: ${errorMessage(error)}`)
    } finally {
      setIsWorking(false)
    }
  }

  function clear() {
    setName("")
    setEmail("")
    setPassphrase("")
    setKeys(null)
    toast.info("Generated key material cleared from the page")
  }

  return (
    <div className="workspace-grid">
      <form onSubmit={generate} className="space-y-5" aria-busy={isWorking}>
        <div>
          <p className="eyebrow">New identity</p>
          <h2 className="workspace-title">Generate a PGP key pair</h2>
          <p className="workspace-copy">
            Create a public key to share and a passphrase-protected private key to keep secret.
          </p>
        </div>

        <div className="grid gap-4 sm:grid-cols-2">
          <div className="field-group">
            <Label htmlFor="identity-name">Name <span className="font-normal text-muted-foreground">(optional)</span></Label>
            <Input
              id="identity-name"
              value={name}
              onChange={(event) => setName(event.target.value)}
              placeholder="Your name"
              autoComplete="name"
              className="h-11"
            />
          </div>
          <div className="field-group">
            <Label htmlFor="identity-email">Email address</Label>
            <Input
              id="identity-email"
              type="email"
              value={email}
              onChange={(event) => setEmail(event.target.value)}
              placeholder="you@example.com"
              autoComplete="email"
              required
              className="h-11"
            />
          </div>
        </div>

        <div className="field-group">
          <Label htmlFor="key-passphrase">Private-key passphrase</Label>
          <SecretInput
            id="key-passphrase"
            value={passphrase}
            onChange={setPassphrase}
            placeholder="At least 12 characters"
          />
          <p className="field-help">This passphrase cannot be recovered. Store it separately from the private key.</p>
        </div>

        <div className="field-group">
          <Label htmlFor="key-algorithm">Algorithm</Label>
          <Select value={algorithm} onValueChange={setAlgorithm}>
            <SelectTrigger id="key-algorithm" className="h-11 w-full">
              <SelectValue />
            </SelectTrigger>
            <SelectContent>
              <SelectItem value="curve25519Legacy">Curve25519 (recommended)</SelectItem>
              <SelectItem value="nistP256">NIST P-256 · broad compatibility</SelectItem>
              <SelectItem value="nistP384">NIST P-384</SelectItem>
              <SelectItem value="nistP521">NIST P-521</SelectItem>
              <SelectItem value="rsa4096">RSA 4096 (legacy compatibility)</SelectItem>
            </SelectContent>
          </Select>
        </div>

        <div className="flex flex-wrap gap-3 pt-1">
          <Button type="submit" size="lg" disabled={isWorking}>
            {isWorking ? <LoaderCircle className="animate-spin" aria-hidden="true" /> : <KeyRound aria-hidden="true" />}
            {isWorking ? "Generating…" : "Generate key pair"}
          </Button>
          <Button type="button" variant="ghost" size="lg" onClick={clear}>
            <Trash2 aria-hidden="true" />
            Clear
          </Button>
        </div>
      </form>

      <aside className="guidance-card">
        <FileKey className="size-6 text-primary" aria-hidden="true" />
        <h3>Your key files</h3>
        <ol>
          <li>Share only the public `.asc` file.</li>
          <li>Keep the private `.asc` file and passphrase secret.</li>
          <li>Save the revocation certificate somewhere safe.</li>
        </ol>
      </aside>

      {keys ? (
        <div className="col-span-full space-y-4 border-t border-border pt-7">
          <div className="fingerprint-row">
            <Check className="size-5 text-primary" aria-hidden="true" />
            <div>
              <p className="text-sm font-semibold">Key fingerprint</p>
              <code>{keys.fingerprint}</code>
            </div>
          </div>
          <ResultBlock title="Public key" value={keys.publicKey} filename={`${keys.fileStem}-public.asc`} />
          <ResultBlock
            title="Private key"
            value={keys.privateKey}
            filename={`${keys.fileStem}-private.asc`}
            warning="Keep this file private. Anyone with it and its passphrase can decrypt your messages."
          />
          <ResultBlock
            title="Revocation certificate"
            value={keys.revocationCertificate}
            filename={`${keys.fileStem}-revocation.asc`}
          />
        </div>
      ) : null}
    </div>
  )
}

function EncryptWorkspace() {
  const [publicKey, setPublicKey] = useState("")
  const [message, setMessage] = useState("")
  const [signMessage, setSignMessage] = useState(false)
  const [privateKey, setPrivateKey] = useState("")
  const [passphrase, setPassphrase] = useState("")
  const [encrypted, setEncrypted] = useState("")
  const [isWorking, setIsWorking] = useState(false)

  async function encrypt(event: React.FormEvent) {
    event.preventDefault()
    if (!publicKey.trim() || !message) {
      toast.error("Add the recipient’s public key and a message.")
      return
    }
    if (signMessage && !privateKey.trim()) {
      toast.error("Add your private key to sign this message.")
      return
    }

    setIsWorking(true)
    try {
      const encryptionKey = await readPublicKey(publicKey)
      const signingKey = signMessage ? await unlockPrivateKey(privateKey, passphrase) : undefined
      const messageObject = await openpgp.createMessage({ text: message })
      const ciphertext = await openpgp.encrypt({
        message: messageObject,
        encryptionKeys: encryptionKey,
        signingKeys: signingKey,
        format: "armored",
      })
      setEncrypted(ciphertext)
      toast.success(signMessage ? "Message encrypted and signed locally" : "Message encrypted locally")
    } catch (error) {
      toast.error(`Encryption failed: ${errorMessage(error)}`)
    } finally {
      setIsWorking(false)
    }
  }

  function clear() {
    setPublicKey("")
    setMessage("")
    setSignMessage(false)
    setPrivateKey("")
    setPassphrase("")
    setEncrypted("")
    toast.info("Encryption fields cleared")
  }

  return (
    <div className="workspace-grid">
      <form onSubmit={encrypt} className="space-y-5" aria-busy={isWorking}>
        <div>
          <p className="eyebrow">For a recipient</p>
          <h2 className="workspace-title">Encrypt a message</h2>
          <p className="workspace-copy">
            Encryption uses the recipient’s public key. Only their corresponding private key can decrypt the result.
          </p>
        </div>

        <div className="field-group">
          <div className="field-heading">
            <Label htmlFor="recipient-key">Recipient’s public key</Label>
            <ImportFile id="recipient-key-file" label="Load key attachment" accept={keyFileTypes} onLoad={setPublicKey} />
          </div>
          <Textarea
            id="recipient-key"
            value={publicKey}
            onChange={(event) => setPublicKey(event.target.value)}
            placeholder="-----BEGIN PGP PUBLIC KEY BLOCK-----"
            spellCheck={false}
            className="code-field min-h-40"
          />
        </div>

        <div className="option-card">
          <Checkbox
            id="sign-encrypted-message"
            checked={signMessage}
            onCheckedChange={(checked) => setSignMessage(checked === true)}
          />
          <div>
            <Label htmlFor="sign-encrypted-message">Sign with my private key</Label>
            <p>Lets the recipient verify who sent the message and that it was not altered.</p>
          </div>
        </div>

        {signMessage ? (
          <div className="nested-fields">
            <div className="field-group">
              <div className="field-heading">
                <Label htmlFor="encrypt-signing-key">Your private signing key</Label>
                <ImportFile
                  id="encrypt-signing-key-file"
                  label="Load private key"
                  accept={keyFileTypes}
                  onLoad={setPrivateKey}
                />
              </div>
              <Textarea
                id="encrypt-signing-key"
                value={privateKey}
                onChange={(event) => setPrivateKey(event.target.value)}
                placeholder="-----BEGIN PGP PRIVATE KEY BLOCK-----"
                spellCheck={false}
                autoComplete="off"
                className="code-field min-h-36"
              />
            </div>
            <div className="field-group">
              <Label htmlFor="encrypt-sign-passphrase">Private-key passphrase</Label>
              <SecretInput
                id="encrypt-sign-passphrase"
                value={passphrase}
                onChange={setPassphrase}
                placeholder="Your private-key passphrase"
              />
            </div>
          </div>
        ) : null}

        <div className="field-group">
          <div className="field-heading">
            <Label htmlFor="plain-message">Message</Label>
            <ImportFile
              id="plain-message-file"
              label="Load text file"
              accept=".txt,.md,.asc,text/plain,text/markdown"
              onLoad={setMessage}
            />
          </div>
          <Textarea
            id="plain-message"
            value={message}
            onChange={(event) => setMessage(event.target.value)}
            placeholder="Write or paste the message to encrypt…"
            className="min-h-44"
          />
        </div>

        <div className="flex flex-wrap gap-3 pt-1">
          <Button type="submit" size="lg" disabled={isWorking}>
            {isWorking ? <LoaderCircle className="animate-spin" aria-hidden="true" /> : <LockKeyhole aria-hidden="true" />}
            {isWorking ? "Encrypting…" : "Encrypt message"}
          </Button>
          <Button type="button" variant="ghost" size="lg" onClick={clear}>
            <Trash2 aria-hidden="true" />
            Clear
          </Button>
        </div>
      </form>

      <aside className="guidance-card">
        <Mail className="size-6 text-primary" aria-hidden="true" />
        <h3>Send it by email</h3>
        <ol>
          <li>Load the recipient’s public-key attachment.</li>
          <li>Encrypt the message on this page.</li>
          <li>Download the encrypted `.asc` file and attach it to your email.</li>
        </ol>
        <p>Email providers will see the attachment, but not its encrypted contents.</p>
      </aside>

      {encrypted ? (
        <div className="col-span-full border-t border-border pt-7">
          <ResultBlock
            title={signMessage ? "Encrypted and signed message" : "Encrypted message"}
            value={encrypted}
            filename="encrypted-message.asc"
          />
        </div>
      ) : null}
    </div>
  )
}

function DecryptWorkspace() {
  const [encryptedMessage, setEncryptedMessage] = useState("")
  const [privateKey, setPrivateKey] = useState("")
  const [passphrase, setPassphrase] = useState("")
  const [verifySender, setVerifySender] = useState(false)
  const [senderPublicKey, setSenderPublicKey] = useState("")
  const [decrypted, setDecrypted] = useState("")
  const [verification, setVerification] = useState<SignatureSummary | null>(null)
  const [unverifiedSignature, setUnverifiedSignature] = useState(false)
  const [isWorking, setIsWorking] = useState(false)

  async function decrypt(event: React.FormEvent) {
    event.preventDefault()
    if (!encryptedMessage.trim() || !privateKey.trim()) {
      toast.error("Add the encrypted message and its corresponding private key.")
      return
    }
    if (verifySender && !senderPublicKey.trim()) {
      toast.error("Add the sender’s public key to verify their signature.")
      return
    }

    setIsWorking(true)
    setVerification(null)
    setUnverifiedSignature(false)
    try {
      const decryptionKey = await unlockPrivateKey(privateKey, passphrase)
      const verificationKey = verifySender ? await readPublicKey(senderPublicKey) : undefined
      const messageObject = await openpgp.readMessage({ armoredMessage: encryptedMessage.trim() })
      const result = await openpgp.decrypt({
        message: messageObject,
        decryptionKeys: decryptionKey,
        verificationKeys: verificationKey,
        expectSigned: verifySender || undefined,
        format: "utf8",
      })
      if (verifySender && verificationKey) {
        const keyIds = await verifySignatureChecks(result.signatures)
        setVerification({ fingerprint: groupedFingerprint(verificationKey), keyIds })
      } else {
        setUnverifiedSignature(result.signatures.length > 0)
      }
      setDecrypted(result.data)
      toast.success(verifySender ? "Message decrypted and signature verified" : "Message decrypted locally")
    } catch (error) {
      toast.error(`Decryption failed: ${errorMessage(error)}`)
    } finally {
      setIsWorking(false)
    }
  }

  function clear() {
    setEncryptedMessage("")
    setPrivateKey("")
    setPassphrase("")
    setVerifySender(false)
    setSenderPublicKey("")
    setDecrypted("")
    setVerification(null)
    setUnverifiedSignature(false)
    toast.info("Private key and message cleared from the page")
  }

  return (
    <div className="workspace-grid">
      <form onSubmit={decrypt} className="space-y-5" aria-busy={isWorking}>
        <div>
          <p className="eyebrow">For you</p>
          <h2 className="workspace-title">Decrypt a message</h2>
          <p className="workspace-copy">Load the encrypted attachment and your private key. Neither is uploaded or stored.</p>
        </div>

        <div className="field-group">
          <div className="field-heading">
            <Label htmlFor="encrypted-message">Encrypted PGP message</Label>
            <ImportFile
              id="encrypted-message-file"
              label="Load encrypted attachment"
              accept={messageFileTypes}
              onLoad={setEncryptedMessage}
            />
          </div>
          <Textarea
            id="encrypted-message"
            value={encryptedMessage}
            onChange={(event) => setEncryptedMessage(event.target.value)}
            placeholder="-----BEGIN PGP MESSAGE-----"
            spellCheck={false}
            className="code-field min-h-40"
          />
        </div>

        <div className="option-card">
          <Checkbox
            id="verify-encrypted-message"
            checked={verifySender}
            onCheckedChange={(checked) => setVerifySender(checked === true)}
          />
          <div>
            <Label htmlFor="verify-encrypted-message">Verify the sender’s signature</Label>
            <p>Use the sender’s public key. Decryption fails if the message is unsigned or the signature is invalid.</p>
          </div>
        </div>

        {verifySender ? (
          <div className="nested-fields">
            <div className="field-group">
              <div className="field-heading">
                <Label htmlFor="decrypt-verification-key">Sender’s public key</Label>
                <ImportFile
                  id="decrypt-verification-key-file"
                  label="Load public key"
                  accept={keyFileTypes}
                  onLoad={setSenderPublicKey}
                />
              </div>
              <Textarea
                id="decrypt-verification-key"
                value={senderPublicKey}
                onChange={(event) => setSenderPublicKey(event.target.value)}
                placeholder="-----BEGIN PGP PUBLIC KEY BLOCK-----"
                spellCheck={false}
                className="code-field min-h-36"
              />
            </div>
          </div>
        ) : null}

        <div className="field-group">
          <div className="field-heading">
            <Label htmlFor="private-key">Your private key</Label>
            <ImportFile id="private-key-file" label="Load private-key attachment" accept={keyFileTypes} onLoad={setPrivateKey} />
          </div>
          <Textarea
            id="private-key"
            value={privateKey}
            onChange={(event) => setPrivateKey(event.target.value)}
            placeholder="-----BEGIN PGP PRIVATE KEY BLOCK-----"
            spellCheck={false}
            autoComplete="off"
            className="code-field min-h-40"
          />
        </div>

        <div className="field-group">
          <Label htmlFor="decrypt-passphrase">
            Private-key passphrase <span className="font-normal text-muted-foreground">(if protected)</span>
          </Label>
          <SecretInput
            id="decrypt-passphrase"
            value={passphrase}
            onChange={setPassphrase}
            placeholder="Your private-key passphrase"
          />
        </div>

        <div className="flex flex-wrap gap-3 pt-1">
          <Button type="submit" size="lg" disabled={isWorking}>
            {isWorking ? <LoaderCircle className="animate-spin" aria-hidden="true" /> : <UnlockKeyhole aria-hidden="true" />}
            {isWorking ? "Decrypting…" : "Decrypt message"}
          </Button>
          <Button type="button" variant="ghost" size="lg" onClick={clear}>
            <Trash2 aria-hidden="true" />
            Clear
          </Button>
        </div>
      </form>

      <aside className="guidance-card warning-card">
        <ShieldCheck className="size-6 text-primary" aria-hidden="true" />
        <h3>Private means private</h3>
        <p>Never email your private key or its passphrase. Load them only on a device you trust, then clear this page when finished.</p>
      </aside>

      {decrypted ? (
        <div className="col-span-full space-y-4 border-t border-border pt-7">
          {verification ? <VerificationBanner summary={verification} /> : null}
          {unverifiedSignature ? (
            <p className="signature-note">This message contains a signature, but no public key was supplied to verify it.</p>
          ) : null}
          <ResultBlock title="Decrypted message" value={decrypted} filename="decrypted-message.txt" />
        </div>
      ) : null}
    </div>
  )
}

function SignTextPanel() {
  const [message, setMessage] = useState("")
  const [privateKey, setPrivateKey] = useState("")
  const [passphrase, setPassphrase] = useState("")
  const [signedMessage, setSignedMessage] = useState("")
  const [isWorking, setIsWorking] = useState(false)

  async function sign(event: React.FormEvent) {
    event.preventDefault()
    if (!message || !privateKey.trim()) {
      toast.error("Add a message and your private signing key.")
      return
    }

    setIsWorking(true)
    try {
      const signingKey = await unlockPrivateKey(privateKey, passphrase)
      const cleartextMessage = await openpgp.createCleartextMessage({ text: message })
      const result = await openpgp.sign({ message: cleartextMessage, signingKeys: signingKey, format: "armored" })
      setSignedMessage(result)
      toast.success("Message signed locally")
    } catch (error) {
      toast.error(`Signing failed: ${errorMessage(error)}`)
    } finally {
      setIsWorking(false)
    }
  }

  function clear() {
    setMessage("")
    setPrivateKey("")
    setPassphrase("")
    setSignedMessage("")
    toast.info("Signing fields cleared")
  }

  return (
    <div className="workspace-grid action-panel">
      <form onSubmit={sign} className="space-y-5" aria-busy={isWorking}>
        <div className="field-group">
          <div className="field-heading">
            <Label htmlFor="message-to-sign">Message to sign</Label>
            <ImportFile
              id="message-to-sign-file"
              label="Load text file"
              accept=".txt,.md,.asc,text/plain,text/markdown"
              onLoad={setMessage}
            />
          </div>
          <Textarea
            id="message-to-sign"
            value={message}
            onChange={(event) => setMessage(event.target.value)}
            placeholder="Write or paste the message to sign…"
            className="min-h-44"
          />
        </div>

        <div className="field-group">
          <div className="field-heading">
            <Label htmlFor="text-signing-key">Your private signing key</Label>
            <ImportFile id="text-signing-key-file" label="Load private key" accept={keyFileTypes} onLoad={setPrivateKey} />
          </div>
          <Textarea
            id="text-signing-key"
            value={privateKey}
            onChange={(event) => setPrivateKey(event.target.value)}
            placeholder="-----BEGIN PGP PRIVATE KEY BLOCK-----"
            spellCheck={false}
            autoComplete="off"
            className="code-field min-h-40"
          />
        </div>

        <div className="field-group">
          <Label htmlFor="text-signing-passphrase">Private-key passphrase</Label>
          <SecretInput
            id="text-signing-passphrase"
            value={passphrase}
            onChange={setPassphrase}
            placeholder="Your private-key passphrase"
          />
        </div>

        <div className="flex flex-wrap gap-3 pt-1">
          <Button type="submit" size="lg" disabled={isWorking}>
            {isWorking ? <LoaderCircle className="animate-spin" aria-hidden="true" /> : <PenLine aria-hidden="true" />}
            {isWorking ? "Signing…" : "Sign message"}
          </Button>
          <Button type="button" variant="ghost" size="lg" onClick={clear}>
            <Trash2 aria-hidden="true" /> Clear
          </Button>
        </div>
      </form>

      <aside className="guidance-card">
        <PenLine className="size-6 text-primary" aria-hidden="true" />
        <h3>What a signature proves</h3>
        <p>A valid signature links the message to your private key and reveals any later change. It does not hide the message.</p>
      </aside>

      {signedMessage ? (
        <div className="col-span-full border-t border-border pt-7">
          <ResultBlock
            title="Cleartext-signed message"
            value={signedMessage}
            filename="signed-message.asc"
            type="application/pgp-signature;charset=utf-8"
          />
        </div>
      ) : null}
    </div>
  )
}

function VerifyTextPanel() {
  const [signedMessage, setSignedMessage] = useState("")
  const [publicKey, setPublicKey] = useState("")
  const [verifiedText, setVerifiedText] = useState("")
  const [verification, setVerification] = useState<SignatureSummary | null>(null)
  const [isWorking, setIsWorking] = useState(false)

  async function verify(event: React.FormEvent) {
    event.preventDefault()
    if (!signedMessage.trim() || !publicKey.trim()) {
      toast.error("Add the signed message and the sender’s public key.")
      return
    }

    setIsWorking(true)
    setVerification(null)
    setVerifiedText("")
    try {
      const verificationKey = await readPublicKey(publicKey)
      const messageObject = await openpgp.readCleartextMessage({ cleartextMessage: signedMessage.trim() })
      const result = await openpgp.verify({ message: messageObject, verificationKeys: verificationKey })
      const keyIds = await verifySignatureChecks(result.signatures)
      setVerification({ fingerprint: groupedFingerprint(verificationKey), keyIds })
      setVerifiedText(result.data)
      toast.success("Message signature verified")
    } catch (error) {
      toast.error(`Verification failed: ${errorMessage(error)}`)
    } finally {
      setIsWorking(false)
    }
  }

  function clear() {
    setSignedMessage("")
    setPublicKey("")
    setVerifiedText("")
    setVerification(null)
    toast.info("Verification fields cleared")
  }

  return (
    <div className="workspace-grid action-panel">
      <form onSubmit={verify} className="space-y-5" aria-busy={isWorking}>
        <div className="field-group">
          <div className="field-heading">
            <Label htmlFor="signed-text-message">Signed PGP message</Label>
            <ImportFile
              id="signed-text-message-file"
              label="Load signed attachment"
              accept={messageFileTypes}
              onLoad={setSignedMessage}
            />
          </div>
          <Textarea
            id="signed-text-message"
            value={signedMessage}
            onChange={(event) => setSignedMessage(event.target.value)}
            placeholder="-----BEGIN PGP SIGNED MESSAGE-----"
            spellCheck={false}
            className="code-field min-h-44"
          />
        </div>

        <div className="field-group">
          <div className="field-heading">
            <Label htmlFor="text-verification-key">Sender’s public key</Label>
            <ImportFile id="text-verification-key-file" label="Load public key" accept={keyFileTypes} onLoad={setPublicKey} />
          </div>
          <Textarea
            id="text-verification-key"
            value={publicKey}
            onChange={(event) => setPublicKey(event.target.value)}
            placeholder="-----BEGIN PGP PUBLIC KEY BLOCK-----"
            spellCheck={false}
            className="code-field min-h-40"
          />
        </div>

        <div className="flex flex-wrap gap-3 pt-1">
          <Button type="submit" size="lg" disabled={isWorking}>
            {isWorking ? <LoaderCircle className="animate-spin" aria-hidden="true" /> : <BadgeCheck aria-hidden="true" />}
            {isWorking ? "Verifying…" : "Verify signature"}
          </Button>
          <Button type="button" variant="ghost" size="lg" onClick={clear}>
            <Trash2 aria-hidden="true" /> Clear
          </Button>
        </div>
      </form>

      <aside className="guidance-card">
        <BadgeCheck className="size-6 text-primary" aria-hidden="true" />
        <h3>Check the fingerprint</h3>
        <p>A valid signature only proves which key signed the message. Compare its fingerprint through a trusted channel before trusting the identity.</p>
      </aside>

      {verification ? (
        <div className="col-span-full space-y-4 border-t border-border pt-7">
          <VerificationBanner summary={verification} />
          <ResultBlock
            title="Verified message"
            value={verifiedText}
            filename="verified-message.txt"
            type="text/plain;charset=utf-8"
          />
        </div>
      ) : null}
    </div>
  )
}

function SignaturesWorkspace() {
  return (
    <div className="space-y-6">
      <div>
        <p className="eyebrow">Authenticity and integrity</p>
        <h2 className="workspace-title">Sign or verify a message</h2>
        <p className="workspace-copy">Sign with a private key. Verify with the matching public key.</p>
      </div>
      <Tabs defaultValue="sign-text">
        <TabsList className="action-tabs" aria-label="Signature tools">
          <TabsTrigger value="sign-text"><PenLine aria-hidden="true" />Sign</TabsTrigger>
          <TabsTrigger value="verify-text"><BadgeCheck aria-hidden="true" />Verify</TabsTrigger>
        </TabsList>
        <TabsContent value="sign-text"><SignTextPanel /></TabsContent>
        <TabsContent value="verify-text"><VerifyTextPanel /></TabsContent>
      </Tabs>
    </div>
  )
}

function EncryptFilePanel() {
  const [file, setFile] = useState<File | null>(null)
  const [publicKey, setPublicKey] = useState("")
  const [signFile, setSignFile] = useState(false)
  const [privateKey, setPrivateKey] = useState("")
  const [passphrase, setPassphrase] = useState("")
  const [progress, setProgress] = useState(0)
  const [completion, setCompletion] = useState("")
  const [isWorking, setIsWorking] = useState(false)

  async function encrypt(event: React.FormEvent) {
    event.preventDefault()
    if (!file || !publicKey.trim()) {
      toast.error("Choose a file and add the recipient’s public key.")
      return
    }
    if (signFile && !privateKey.trim()) {
      toast.error("Add your private key to sign this file.")
      return
    }

    const outputName = encryptedFilename(file.name)
    let handle: LocalFileHandle | null
    try {
      handle = await chooseOutputHandle(outputName)
    } catch (error) {
      if (isCancelled(error)) return
      toast.error(errorMessage(error))
      return
    }

    setIsWorking(true)
    setProgress(0)
    setCompletion("")
    try {
      const encryptionKey = await readPublicKey(publicKey)
      const signingKey = signFile ? await unlockPrivateKey(privateKey, passphrase) : undefined
      const message = await openpgp.createMessage({
        binary: trackedFileStream(file, setProgress),
        filename: safeOutputFilename(file.name, "attachment"),
      })
      const output = await openpgp.encrypt({
        message,
        encryptionKeys: encryptionKey,
        signingKeys: signingKey,
        format: "binary",
      })
      const mode = await writeBinaryOutput({
        output,
        filename: outputName,
        type: "application/pgp-encrypted",
        handle,
      })
      setProgress(100)
      setCompletion(`${outputName} ${mode === "streamed" ? "was written directly to disk" : "was sent to your browser downloads"}.`)
      toast.success(signFile ? "File encrypted and signed locally" : "File encrypted locally")
    } catch (error) {
      toast.error(`File encryption failed: ${errorMessage(error)}`)
    } finally {
      setIsWorking(false)
    }
  }

  function clear() {
    setFile(null)
    setPublicKey("")
    setSignFile(false)
    setPrivateKey("")
    setPassphrase("")
    setProgress(0)
    setCompletion("")
    toast.info("File encryption fields cleared")
  }

  return (
    <div className="workspace-grid action-panel">
      <form onSubmit={encrypt} className="space-y-5" aria-busy={isWorking}>
        <BinaryFilePicker id="file-to-encrypt" label="Choose a file to encrypt" file={file} onSelect={setFile} />

        <div className="field-group">
          <div className="field-heading">
            <Label htmlFor="file-recipient-key">Recipient’s public key</Label>
            <ImportFile id="file-recipient-key-attachment" label="Load public key" accept={keyFileTypes} onLoad={setPublicKey} />
          </div>
          <Textarea
            id="file-recipient-key"
            value={publicKey}
            onChange={(event) => setPublicKey(event.target.value)}
            placeholder="-----BEGIN PGP PUBLIC KEY BLOCK-----"
            spellCheck={false}
            className="code-field min-h-36"
          />
        </div>

        <div className="option-card">
          <Checkbox id="sign-encrypted-file" checked={signFile} onCheckedChange={(checked) => setSignFile(checked === true)} />
          <div>
            <Label htmlFor="sign-encrypted-file">Encrypt and sign in one operation</Label>
            <p>The recipient can decrypt the file and verify your signature with your public key.</p>
          </div>
        </div>

        {signFile ? (
          <div className="nested-fields">
            <div className="field-group">
              <div className="field-heading">
                <Label htmlFor="file-encrypt-signing-key">Your private signing key</Label>
                <ImportFile
                  id="file-encrypt-signing-key-attachment"
                  label="Load private key"
                  accept={keyFileTypes}
                  onLoad={setPrivateKey}
                />
              </div>
              <Textarea
                id="file-encrypt-signing-key"
                value={privateKey}
                onChange={(event) => setPrivateKey(event.target.value)}
                placeholder="-----BEGIN PGP PRIVATE KEY BLOCK-----"
                spellCheck={false}
                autoComplete="off"
                className="code-field min-h-36"
              />
            </div>
            <div className="field-group">
              <Label htmlFor="file-encrypt-signing-passphrase">Private-key passphrase</Label>
              <SecretInput
                id="file-encrypt-signing-passphrase"
                value={passphrase}
                onChange={setPassphrase}
                placeholder="Your private-key passphrase"
              />
            </div>
          </div>
        ) : null}

        {isWorking ? <OperationProgress progress={progress} label="Encrypting file" /> : null}

        <div className="flex flex-wrap gap-3 pt-1">
          <Button type="submit" size="lg" disabled={isWorking}>
            {isWorking ? <LoaderCircle className="animate-spin" aria-hidden="true" /> : <LockKeyhole aria-hidden="true" />}
            {isWorking ? "Encrypting…" : signFile ? "Encrypt & sign file" : "Encrypt file"}
          </Button>
          <Button type="button" variant="ghost" size="lg" onClick={clear} disabled={isWorking}>
            <Trash2 aria-hidden="true" /> Clear
          </Button>
        </div>
      </form>

      <aside className="guidance-card">
        <Mail className="size-6 text-primary" aria-hidden="true" />
        <h3>Email-ready output</h3>
        <ol>
          <li>The original filename is preserved inside the PGP message.</li>
          <li>A compact binary `.pgp` file is created.</li>
          <li>Attach that file to an email or transfer it another way.</li>
        </ol>
      </aside>

      {completion ? <p className="completion-banner col-span-full"><Check aria-hidden="true" />{completion}</p> : null}
    </div>
  )
}

function DecryptFilePanel() {
  const [file, setFile] = useState<File | null>(null)
  const [privateKey, setPrivateKey] = useState("")
  const [passphrase, setPassphrase] = useState("")
  const [verifySender, setVerifySender] = useState(false)
  const [senderPublicKey, setSenderPublicKey] = useState("")
  const [progress, setProgress] = useState(0)
  const [completion, setCompletion] = useState("")
  const [verification, setVerification] = useState<SignatureSummary | null>(null)
  const [isWorking, setIsWorking] = useState(false)

  async function decrypt(event: React.FormEvent) {
    event.preventDefault()
    if (!file || !privateKey.trim()) {
      toast.error("Choose an encrypted file and add your private key.")
      return
    }
    if (verifySender && !senderPublicKey.trim()) {
      toast.error("Add the sender’s public key to verify the file signature.")
      return
    }

    const suggestedName = decryptedFilename(file.name)
    let handle: LocalFileHandle | null
    try {
      handle = await chooseOutputHandle(suggestedName)
    } catch (error) {
      if (isCancelled(error)) return
      toast.error(errorMessage(error))
      return
    }

    setIsWorking(true)
    setProgress(0)
    setCompletion("")
    setVerification(null)
    try {
      const decryptionKey = await unlockPrivateKey(privateKey, passphrase)
      const verificationKey = verifySender ? await readPublicKey(senderPublicKey) : undefined
      const message = await readFileMessage(file, setProgress)
      const result = await openpgp.decrypt({
        message,
        decryptionKeys: decryptionKey,
        verificationKeys: verificationKey,
        expectSigned: verifySender || undefined,
        format: "binary",
      })
      const outputName = safeOutputFilename(result.filename, suggestedName)
      let verifiedSummary: SignatureSummary | null = null
      const mode = await writeBinaryOutput({
        output: result.data,
        filename: outputName,
        type: "application/octet-stream",
        handle,
        beforeCommit: verifySender && verificationKey
          ? async () => {
              const keyIds = await verifySignatureChecks(result.signatures)
              verifiedSummary = { fingerprint: groupedFingerprint(verificationKey), keyIds }
            }
          : undefined,
      })
      setProgress(100)
      setVerification(verifiedSummary)
      setCompletion(`${outputName} ${mode === "streamed" ? "was written directly to disk" : "was sent to your browser downloads"}.`)
      toast.success(verifySender ? "File decrypted and signature verified" : "File decrypted locally")
    } catch (error) {
      toast.error(`File decryption failed: ${errorMessage(error)}`)
    } finally {
      setIsWorking(false)
    }
  }

  function clear() {
    setFile(null)
    setPrivateKey("")
    setPassphrase("")
    setVerifySender(false)
    setSenderPublicKey("")
    setProgress(0)
    setCompletion("")
    setVerification(null)
    toast.info("File decryption fields cleared")
  }

  return (
    <div className="workspace-grid action-panel">
      <form onSubmit={decrypt} className="space-y-5" aria-busy={isWorking}>
        <BinaryFilePicker
          id="file-to-decrypt"
          label="Choose an encrypted .pgp, .gpg, or .asc file"
          file={file}
          accept=".pgp,.gpg,.asc,application/pgp-encrypted,application/octet-stream"
          onSelect={setFile}
        />

        <div className="field-group">
          <div className="field-heading">
            <Label htmlFor="file-decryption-key">Your private key</Label>
            <ImportFile id="file-decryption-key-attachment" label="Load private key" accept={keyFileTypes} onLoad={setPrivateKey} />
          </div>
          <Textarea
            id="file-decryption-key"
            value={privateKey}
            onChange={(event) => setPrivateKey(event.target.value)}
            placeholder="-----BEGIN PGP PRIVATE KEY BLOCK-----"
            spellCheck={false}
            autoComplete="off"
            className="code-field min-h-36"
          />
        </div>

        <div className="field-group">
          <Label htmlFor="file-decryption-passphrase">Private-key passphrase</Label>
          <SecretInput
            id="file-decryption-passphrase"
            value={passphrase}
            onChange={setPassphrase}
            placeholder="Your private-key passphrase"
          />
        </div>

        <div className="option-card">
          <Checkbox id="verify-decrypted-file" checked={verifySender} onCheckedChange={(checked) => setVerifySender(checked === true)} />
          <div>
            <Label htmlFor="verify-decrypted-file">Require a valid sender signature</Label>
            <p>The output is committed only after the embedded signature has been checked.</p>
          </div>
        </div>

        {verifySender ? (
          <div className="nested-fields">
            <div className="field-group">
              <div className="field-heading">
                <Label htmlFor="file-sender-key">Sender’s public key</Label>
                <ImportFile id="file-sender-key-attachment" label="Load public key" accept={keyFileTypes} onLoad={setSenderPublicKey} />
              </div>
              <Textarea
                id="file-sender-key"
                value={senderPublicKey}
                onChange={(event) => setSenderPublicKey(event.target.value)}
                placeholder="-----BEGIN PGP PUBLIC KEY BLOCK-----"
                spellCheck={false}
                className="code-field min-h-36"
              />
            </div>
          </div>
        ) : null}

        {isWorking ? <OperationProgress progress={progress} label="Decrypting file" /> : null}

        <div className="flex flex-wrap gap-3 pt-1">
          <Button type="submit" size="lg" disabled={isWorking}>
            {isWorking ? <LoaderCircle className="animate-spin" aria-hidden="true" /> : <UnlockKeyhole aria-hidden="true" />}
            {isWorking ? "Decrypting…" : verifySender ? "Decrypt & verify file" : "Decrypt file"}
          </Button>
          <Button type="button" variant="ghost" size="lg" onClick={clear} disabled={isWorking}>
            <Trash2 aria-hidden="true" /> Clear
          </Button>
        </div>
      </form>

      <aside className="guidance-card warning-card">
        <ShieldCheck className="size-6 text-primary" aria-hidden="true" />
        <h3>Keep the secret key local</h3>
        <p>Your private key, passphrase, encrypted file, and decrypted output never leave this browser.</p>
      </aside>

      {completion ? (
        <div className="col-span-full space-y-4">
          {verification ? <VerificationBanner summary={verification} title="File signature verified" /> : null}
          <p className="completion-banner"><Check aria-hidden="true" />{completion}</p>
        </div>
      ) : null}
    </div>
  )
}

function SignFilePanel() {
  const [file, setFile] = useState<File | null>(null)
  const [privateKey, setPrivateKey] = useState("")
  const [passphrase, setPassphrase] = useState("")
  const [signature, setSignature] = useState("")
  const [signatureFilename, setSignatureFilename] = useState("attachment.sig.asc")
  const [progress, setProgress] = useState(0)
  const [isWorking, setIsWorking] = useState(false)

  async function sign(event: React.FormEvent) {
    event.preventDefault()
    if (!file || !privateKey.trim()) {
      toast.error("Choose a file and add your private signing key.")
      return
    }

    setIsWorking(true)
    setProgress(0)
    setSignature("")
    try {
      const signingKey = await unlockPrivateKey(privateKey, passphrase)
      const message = await openpgp.createMessage({
        binary: trackedFileStream(file, setProgress),
        filename: safeOutputFilename(file.name, "attachment"),
      })
      const output = await openpgp.sign({
        message,
        signingKeys: signingKey,
        detached: true,
        format: "armored",
      })
      setSignature(await collectText(output))
      setSignatureFilename(`${safeOutputFilename(file.name, "attachment")}.sig.asc`)
      setProgress(100)
      toast.success("Detached file signature created locally")
    } catch (error) {
      toast.error(`File signing failed: ${errorMessage(error)}`)
    } finally {
      setIsWorking(false)
    }
  }

  function clear() {
    setFile(null)
    setPrivateKey("")
    setPassphrase("")
    setSignature("")
    setProgress(0)
    toast.info("File signing fields cleared")
  }

  return (
    <div className="workspace-grid action-panel">
      <form onSubmit={sign} className="space-y-5" aria-busy={isWorking}>
        <BinaryFilePicker id="file-to-sign" label="Choose a file to sign" file={file} onSelect={setFile} />

        <div className="field-group">
          <div className="field-heading">
            <Label htmlFor="file-signing-key">Your private signing key</Label>
            <ImportFile id="file-signing-key-attachment" label="Load private key" accept={keyFileTypes} onLoad={setPrivateKey} />
          </div>
          <Textarea
            id="file-signing-key"
            value={privateKey}
            onChange={(event) => setPrivateKey(event.target.value)}
            placeholder="-----BEGIN PGP PRIVATE KEY BLOCK-----"
            spellCheck={false}
            autoComplete="off"
            className="code-field min-h-36"
          />
        </div>

        <div className="field-group">
          <Label htmlFor="file-signing-passphrase">Private-key passphrase</Label>
          <SecretInput
            id="file-signing-passphrase"
            value={passphrase}
            onChange={setPassphrase}
            placeholder="Your private-key passphrase"
          />
        </div>

        {isWorking ? <OperationProgress progress={progress} label="Signing file" /> : null}

        <div className="flex flex-wrap gap-3 pt-1">
          <Button type="submit" size="lg" disabled={isWorking}>
            {isWorking ? <LoaderCircle className="animate-spin" aria-hidden="true" /> : <PenLine aria-hidden="true" />}
            {isWorking ? "Signing…" : "Sign file"}
          </Button>
          <Button type="button" variant="ghost" size="lg" onClick={clear} disabled={isWorking}>
            <Trash2 aria-hidden="true" /> Clear
          </Button>
        </div>
      </form>

      <aside className="guidance-card">
        <FileKey className="size-6 text-primary" aria-hidden="true" />
        <h3>Send both files</h3>
        <p>A detached signature does not contain the original file. Send the unchanged original plus the small `.sig.asc` signature.</p>
      </aside>

      {signature ? (
        <div className="col-span-full border-t border-border pt-7">
          <ResultBlock
            title="Detached PGP signature"
            value={signature}
            filename={signatureFilename}
            type="application/pgp-signature;charset=utf-8"
          />
        </div>
      ) : null}
    </div>
  )
}

function VerifyFilePanel() {
  const [file, setFile] = useState<File | null>(null)
  const [signature, setSignature] = useState("")
  const [publicKey, setPublicKey] = useState("")
  const [verification, setVerification] = useState<SignatureSummary | null>(null)
  const [progress, setProgress] = useState(0)
  const [isWorking, setIsWorking] = useState(false)

  async function verify(event: React.FormEvent) {
    event.preventDefault()
    if (!file || !signature.trim() || !publicKey.trim()) {
      toast.error("Choose the original file, its detached signature, and the sender’s public key.")
      return
    }

    setIsWorking(true)
    setProgress(0)
    setVerification(null)
    try {
      const verificationKey = await readPublicKey(publicKey)
      const signatureObject = await openpgp.readSignature({ armoredSignature: signature.trim() })
      const message = await openpgp.createMessage({
        binary: trackedFileStream(file, setProgress),
        filename: safeOutputFilename(file.name, "attachment"),
      })
      const result = await openpgp.verify({
        message,
        signature: signatureObject,
        verificationKeys: verificationKey,
        format: "binary",
      })
      await consumeBinary(result.data)
      const keyIds = await verifySignatureChecks(result.signatures)
      setVerification({ fingerprint: groupedFingerprint(verificationKey), keyIds })
      setProgress(100)
      toast.success("File signature verified")
    } catch (error) {
      toast.error(`File verification failed: ${errorMessage(error)}`)
    } finally {
      setIsWorking(false)
    }
  }

  function clear() {
    setFile(null)
    setSignature("")
    setPublicKey("")
    setVerification(null)
    setProgress(0)
    toast.info("File verification fields cleared")
  }

  return (
    <div className="workspace-grid action-panel">
      <form onSubmit={verify} className="space-y-5" aria-busy={isWorking}>
        <BinaryFilePicker id="file-to-verify" label="Choose the original file" file={file} onSelect={setFile} />

        <div className="field-group">
          <div className="field-heading">
            <Label htmlFor="detached-file-signature">Detached PGP signature</Label>
            <ImportFile
              id="detached-file-signature-attachment"
              label="Load .sig.asc"
              accept={signatureFileTypes}
              onLoad={setSignature}
            />
          </div>
          <Textarea
            id="detached-file-signature"
            value={signature}
            onChange={(event) => setSignature(event.target.value)}
            placeholder="-----BEGIN PGP SIGNATURE-----"
            spellCheck={false}
            className="code-field min-h-36"
          />
        </div>

        <div className="field-group">
          <div className="field-heading">
            <Label htmlFor="file-verification-key">Sender’s public key</Label>
            <ImportFile id="file-verification-key-attachment" label="Load public key" accept={keyFileTypes} onLoad={setPublicKey} />
          </div>
          <Textarea
            id="file-verification-key"
            value={publicKey}
            onChange={(event) => setPublicKey(event.target.value)}
            placeholder="-----BEGIN PGP PUBLIC KEY BLOCK-----"
            spellCheck={false}
            className="code-field min-h-36"
          />
        </div>

        {isWorking ? <OperationProgress progress={progress} label="Verifying file" /> : null}

        <div className="flex flex-wrap gap-3 pt-1">
          <Button type="submit" size="lg" disabled={isWorking}>
            {isWorking ? <LoaderCircle className="animate-spin" aria-hidden="true" /> : <BadgeCheck aria-hidden="true" />}
            {isWorking ? "Verifying…" : "Verify file signature"}
          </Button>
          <Button type="button" variant="ghost" size="lg" onClick={clear} disabled={isWorking}>
            <Trash2 aria-hidden="true" /> Clear
          </Button>
        </div>
      </form>

      <aside className="guidance-card">
        <BadgeCheck className="size-6 text-primary" aria-hidden="true" />
        <h3>The original must be unchanged</h3>
        <p>Even a one-byte difference makes verification fail. Confirm the displayed public-key fingerprint through a trusted channel.</p>
      </aside>

      {verification ? (
        <div className="col-span-full border-t border-border pt-7">
          <VerificationBanner summary={verification} title="File signature verified" />
        </div>
      ) : null}
    </div>
  )
}

function FilesWorkspace() {
  return (
    <div className="space-y-6">
      <div className="file-workspace-heading">
        <div>
          <p className="eyebrow">Email attachments and large files</p>
          <h2 className="workspace-title">Protect any file with OpenPGP</h2>
          <p className="workspace-copy">Encrypt, decrypt, sign, or verify without uploading the attachment.</p>
        </div>
        <StreamingNote />
      </div>
      <Tabs defaultValue="encrypt-file">
        <TabsList className="action-tabs file-action-tabs" aria-label="File PGP tools">
          <TabsTrigger value="encrypt-file"><LockKeyhole aria-hidden="true" />Encrypt</TabsTrigger>
          <TabsTrigger value="decrypt-file"><UnlockKeyhole aria-hidden="true" />Decrypt</TabsTrigger>
          <TabsTrigger value="sign-file"><PenLine aria-hidden="true" />Sign</TabsTrigger>
          <TabsTrigger value="verify-file"><BadgeCheck aria-hidden="true" />Verify</TabsTrigger>
        </TabsList>
        <TabsContent value="encrypt-file"><EncryptFilePanel /></TabsContent>
        <TabsContent value="decrypt-file"><DecryptFilePanel /></TabsContent>
        <TabsContent value="sign-file"><SignFilePanel /></TabsContent>
        <TabsContent value="verify-file"><VerifyFilePanel /></TabsContent>
      </Tabs>
    </div>
  )
}

export default function Home() {
  const [workspace, setWorkspace] = useState<Workspace>("generate")

  return (
    <div className="min-h-screen bg-background text-foreground">
      <header className="site-header">
        <div className="site-shell site-header-inner">
          <a href="#main" className="brand" aria-label="PGP home">
            <span className="brand-lock" aria-hidden="true">🔑</span>
            <strong>PGP</strong>
          </a>
          <div className="header-actions">
            <a
              className="github-mark"
              href="https://github.com/hopeugetherpes/pgp"
              target="_blank"
              rel="noreferrer"
              aria-label="View PGP source on GitHub"
              title="PGP on GitHub"
            >
              <GitHubOutline />
            </a>
          </div>
        </div>
      </header>

      <main id="main" className="site-shell site-main">
        <section className="intro-row">
          <div>
            <h1>OpenPGP encryption, right in your browser.</h1>
            <p>Generate keys, encrypt, decrypt, sign, and verify messages or attachments.</p>
            <p>Nothing leaves your device.</p>
          </div>
        </section>

        <section className="privacy-note" aria-label="Privacy information">
          <ShieldCheck aria-hidden="true" />
          <div>
            <strong>Your data never leaves this device</strong>
            <span>All cryptographic operations run locally. No accounts, uploads, telemetry, or persistent storage.</span>
          </div>
        </section>

        <Tabs value={workspace} onValueChange={(value) => setWorkspace(value as Workspace)}>
          <TabsList className="workspace-tabs" aria-label="PGP tools">
            <TabsTrigger value="generate"><KeyRound aria-hidden="true" />Keys</TabsTrigger>
            <TabsTrigger value="encrypt"><LockKeyhole aria-hidden="true" />Encrypt</TabsTrigger>
            <TabsTrigger value="decrypt"><UnlockKeyhole aria-hidden="true" />Decrypt</TabsTrigger>
            <TabsTrigger value="sign"><PenLine aria-hidden="true" />Sign</TabsTrigger>
            <TabsTrigger value="files"><Files aria-hidden="true" />Files</TabsTrigger>
          </TabsList>

          <div className="workspace-card">
            <TabsContent value="generate"><GenerateWorkspace /></TabsContent>
            <TabsContent value="encrypt"><EncryptWorkspace /></TabsContent>
            <TabsContent value="decrypt"><DecryptWorkspace /></TabsContent>
            <TabsContent value="sign"><SignaturesWorkspace /></TabsContent>
            <TabsContent value="files"><FilesWorkspace /></TabsContent>
          </div>
        </Tabs>

        <footer>
          <div>
            <p className="footer-source">
              <a
                href="https://github.com/hopeugetherpes/pgp"
                target="_blank"
                rel="noopener noreferrer"
              >
                Open source
              </a>
            </p>
            <p>
              <a
                href="https://github.com/hopeugetherpes/pgp/blob/main/LICENSE"
                target="_blank"
                rel="noopener noreferrer"
              >
                CC0
              </a>{" "}
              Public Domain - No Copyright Required
            </p>
            <p className="footer-download" data-offline-download>
              <a
                href="https://pgp.anatole.co/pgp.html"
                download="PGP.html"
                aria-label="Download PGP as a standalone offline HTML file"
              >
                Save offline .html
              </a>{" "}
              ·{" "}
              <a
                href="https://pgp.anatole.co/pgp.html.sha256"
                download="pgp.html.sha256"
                aria-label="Download the SHA-256 checksum for the standalone PGP file"
              >
                SHA-256
              </a>{" "}
              ·{" "}
              <a
                href="https://github.com/hopeugetherpes/pgp/blob/main/OFFLINE.md"
                target="_blank"
                rel="noopener noreferrer"
              >
                Verify
              </a>
            </p>
          </div>
        </footer>
      </main>
      <Toaster position="bottom-center" richColors closeButton />
    </div>
  )
}
