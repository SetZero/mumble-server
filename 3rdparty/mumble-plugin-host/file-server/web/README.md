# file-server web frontend

React + [Material UI 9](https://mui.com/) + [lucide-react](https://lucide.dev/)
source for the HTML pages embedded into the Mumble file-server.

Today this builds a single page — the **password-entry page** served when a
password-protected file is opened in a browser without a ticket — but it is
structured as a normal multi-component app so further pages (admin, "me", file
listings) can be added alongside it.

## How it ties into the Rust build

`npm run build` produces **one self-contained file**, `dist/password.html`:

1. `vite build` bundles the app and `vite-plugin-singlefile` inlines all JS/CSS
   (no external asset requests — required by the page's strict CSP).
2. `scripts/postbuild.mjs` stamps `nonce="__CSP_NONCE__"` onto every `<script>`
   and renames the output to `dist/password.html`.

The crate embeds that file with `include_str!("../../web/dist/password.html")`
(see [`src/http/download.rs`](../src/http/download.rs)) and replaces
`__CSP_NONCE__` with a fresh per-response nonce under
`script-src 'nonce-...'`. Emotion's runtime styles are covered by the page's
`style-src 'unsafe-inline'`.

`dist/password.html` is **committed** so the crate compiles without a Node
toolchain. The file-server's `build.rs` rebuilds it automatically when `npm` is
available and the `web/` sources change (hybrid build):

- No Node present → the committed artifact is used as-is.
- `MUMBLE_FILESERVER_SKIP_WEB_BUILD=1` → skip the npm build entirely.

## Local development

```sh
npm install
npm run dev      # hot-reloading dev server (mock the /auth endpoint yourself)
npm run build    # produce dist/password.html
npm run lint     # type-check only
```
