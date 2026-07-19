// Post-process the single-file Vite output for the file-server:
//
//   1. Strip HTML comments from the static markup so internal build notes are
//      not shipped to the served page (and cannot confuse the nonce stamping).
//   2. Stamp `nonce="__CSP_NONCE__"` onto the inlined entry <script>. The server
//      serves this page under `script-src 'nonce-...'` and replaces the
//      placeholder with a fresh per-response nonce (see src/http/download.rs),
//      so without the attribute the inlined bundle would be blocked.
//   3. Rename index.html -> password.html (the name the crate embeds) and drop
//      any other generated dist artifacts so only the single file remains.

import { readFileSync, writeFileSync, rmSync, readdirSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, resolve } from "node:path";

const webDir = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const distDir = resolve(webDir, "dist");
const inputHtml = resolve(distDir, "index.html");
const outputHtml = resolve(distDir, "password.html");

let html = readFileSync(inputHtml, "utf8");

// The single inlined entry script that vite-plugin-singlefile emits. It is the
// first `<script type="module">` in the document; everything after its opening
// tag is bundled JS (which may itself contain escaped `<script>`/`<!--` text we
// must NOT touch), so we operate on the static-markup prefix and the entry tag
// only, never the bundle body.
const ENTRY_TAG = /<script\b[^>]*\btype="module"[^>]*>/;
const match = ENTRY_TAG.exec(html);
if (!match) {
  throw new Error(
    "postbuild: no inlined `<script type=\"module\">` found - the bundle did " +
      "not inline as expected, so the CSP nonce cannot be stamped.",
  );
}

let prefix = html.slice(0, match.index);
const fromEntry = html.slice(match.index);

// Safe to strip comments here: the prefix is pure markup (the JS/CSS bundle
// lives entirely in `fromEntry`, where stray `<!--` inside string literals would
// otherwise be corrupted).
prefix = prefix.replace(/<!--[\s\S]*?-->/g, "");

// Stamp the nonce onto the entry tag (idempotent).
const stamped = fromEntry.replace(ENTRY_TAG, (tag) =>
  /\bnonce=/.test(tag) ? tag : tag.replace(/^<script/, '<script nonce="__CSP_NONCE__"'),
);

html = prefix + stamped;

const nonceCount = html.split("__CSP_NONCE__").length - 1;
if (nonceCount !== 1) {
  throw new Error(
    `postbuild: expected exactly one __CSP_NONCE__ placeholder after stamping, ` +
      `found ${nonceCount}. The server replaces every occurrence, so a stray one ` +
      `would leak the nonce; aborting.`,
  );
}

const realScripts = html.split("</script>").length - 1;
if (realScripts !== 1) {
  console.warn(
    `postbuild: expected exactly one inlined <script>, found ${realScripts}. ` +
      `Only the first was given a CSP nonce - additional scripts would be blocked.`,
  );
}

writeFileSync(outputHtml, html);

// Keep dist/ to just the one file the crate embeds.
for (const entry of readdirSync(distDir)) {
  if (entry !== "password.html") {
    rmSync(resolve(distDir, entry), { recursive: true, force: true });
  }
}

console.log(`postbuild: wrote ${outputHtml} (CSP nonce stamped on the entry script)`);
