# TServerMonitor web

The dashboard for TServerMonitor: Vite, React 19, TypeScript, and the [Arc](https://uiarc.dev) component library. All UI text is Chinese. The HTTP contract is `../docs/api.md`; `src/api/types.ts` mirrors it.

## Scripts

| Command | What it does |
| --- | --- |
| `pnpm dev` | Dev server. `/api` and `/mcp` are proxied to the daemon at `http://127.0.0.1:8787`. |
| `pnpm dev:mock` | Dev server with generated data and a simulated SSE stream (`vite --mode mock`, see `.env.mock`). No daemon needed. |
| `pnpm build` | `tsc -b` type check, then `vite build` into `dist/`, which the Rust binary embeds. |
| `pnpm lint` | oxlint. |
| `pnpm arc:pro` | Installs the licensed Arc Pro components (see below). |

Routing uses the URL hash (`#/containers`), so the embedded build needs no SPA fallback on the server.

## Arc Pro components

Arc Pro source is licensed and must never be committed. `src/components/arc-pro/` is git-ignored; `arc-pro.json` lists the Pro component names the app uses. Before the first build, run:

```bash
ARC_PRO_TOKEN=<token> pnpm arc:pro
# or put ARC_PRO_TOKEN=<token> in web/.env.local (git-ignored) and run pnpm arc:pro
```

`scripts/install-arc-pro.mjs` runs `npx shadcn@latest add @uiarc-pro/<name>` for every listed name, moves each Pro item's folder into `src/components/arc-pro/<name>/`, and rewrites its relative imports so free dependencies resolve from `src/components/arc/`. It stops with a clear message when the token is missing.

Free Arc components live in `src/components/arc/` and are committed. To add or update one, use the public registry URL, for example `npx shadcn@latest add https://uiarc.dev/r/badge.json`.

`components.json` uses the Radix-compatible `new-york` style on purpose: with a Base UI style (`base-*`) the shadcn CLI rewrites Arc's Radix `asChild` props into `render`, which breaks the dialog, drawer, and tooltip.

## Auth and live data

Requests send `Authorization: Bearer <token>` from `localStorage.tsm_token`. A 401 opens a token dialog. One shared `EventSource` on `/api/v1/stream` (with `?token=` when set) feeds the live charts and keeps the last 360 metric samples.
