import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";
import { viteSingleFile } from "vite-plugin-singlefile";

// The file-server embeds the built page with `include_str!` and serves it under
// a strict nonce CSP, so the output must be ONE self-contained HTML file with no
// external asset requests. `vite-plugin-singlefile` inlines all JS/CSS; a
// post-build step (scripts/postbuild.mjs) then stamps the `__CSP_NONCE__`
// placeholder onto every <script> and renames the file to `password.html`.
export default defineConfig({
  plugins: [react(), viteSingleFile()],
  build: {
    target: "es2022",
    cssCodeSplit: false,
    assetsInlineLimit: 100_000_000,
    chunkSizeWarningLimit: 4096,
    rollupOptions: {
      output: { inlineDynamicImports: true },
    },
  },
});
