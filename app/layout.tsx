import type { Metadata } from "next";
import "./globals.css";

export const metadata: Metadata = {
  title: "PGP - Generate keys, encrypt, decrypt, sign, and verify messages or attachments. Nothing leaves your device.",
  description:
    "Generate keys, encrypt, decrypt, sign, and verify messages or attachments. Nothing leaves your device.",
  applicationName: "PGP",
  icons: {
    icon: "/favicon.svg",
    shortcut: "/favicon.svg",
  },
};

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    <html lang="en">
      <head>
        <meta
          httpEquiv="Content-Security-Policy"
          content="default-src 'self' data: blob:; connect-src 'none'; object-src 'none'; base-uri 'self'; form-action 'none'; frame-ancestors 'none'; worker-src 'self' blob:; script-src 'self' 'unsafe-inline' 'wasm-unsafe-eval'; style-src 'self' 'unsafe-inline'"
        />
      </head>
      <body>{children}</body>
    </html>
  );
}
