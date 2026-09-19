import { fileURLToPath, URL } from "node:url"
import { defineConfig } from "vite"
import react from "@vitejs/plugin-react"

export default defineConfig({
  root: fileURLToPath(new URL("./static", import.meta.url)),
  publicDir: fileURLToPath(new URL("./public", import.meta.url)),
  base: "./",
  plugins: [react()],
  resolve: {
    alias: {
      "@": fileURLToPath(new URL("./", import.meta.url)),
    },
  },
  build: {
    outDir: fileURLToPath(new URL("./dist", import.meta.url)),
    emptyOutDir: true,
    target: "es2022",
    cssCodeSplit: false,
    modulePreload: false,
    chunkSizeWarningLimit: 1000,
    rollupOptions: {
      output: {
        codeSplitting: false,
        entryFileNames: "assets/pgp.js",
        assetFileNames: (assetInfo) =>
          assetInfo.names?.some((name) => name.endsWith(".css"))
            ? "assets/pgp.css"
            : "assets/[name][extname]",
      },
    },
  },
})
