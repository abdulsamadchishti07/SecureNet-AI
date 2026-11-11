# SecureNet AI React dashboard

React + TypeScript + Vite dashboard. Working component:
`src/App.tsx`. Typed API/session effects
live in `src/{api,usePlatform,types}.ts`; `src/main.tsx` mounts the React root.

Use Node `^20.19.0` or `>=22.12.0` (Vite's requirement). Verification used Node
26.13.0 and npm 12.2.1. Dependencies are exact-pinned in `package-lock.json`.

## Development

Start FastAPI from the repository root:

```bash
.venv/bin/python -m uvicorn backend.main:app --host 127.0.0.1 --port 8010 --workers 1 --no-access-log --log-level warning
```

In another terminal, from the repository root:

```bash
npm --prefix frontend ci
npm --prefix frontend run dev
```

Open `http://127.0.0.1:5173`. Vite proxies `/api` and `/ws/alerts` to loopback 8010,
including WebSocket upgrades. Browser calls stay on the Vite origin, so no extra
CORS origins are required. Vite HMR is separate from the authenticated alert stream.

## Compiled application

```bash
npm --prefix frontend run build
```

This runs strict TypeScript checking and builds `dist/index.html` plus hashed
assets under `dist/static/`. Start/restart FastAPI after the first build, then open
`http://127.0.0.1:8010`. FastAPI serves only the compiled directory, not TSX source,
dependencies or project files. Missing builds return 503 at `/`; the API stays
available. Generated `dist/` and `node_modules/` are ignored by Git.

`npm run preview` previews static build output, not the integrated API proxy. Use
FastAPI for the compiled app or `npm run dev` while developing.

## Checks

```bash
npm --prefix frontend run typecheck
npm --prefix frontend run format:check
npm --prefix frontend run build
.venv/bin/python -m pytest browser_tests -q
```

Browser tests require the compiled build and optional dependencies from
`requirements-browser.txt`. Their SQLite/loopback fixtures are isolated from main
PostgreSQL. Lockfile installation, dependency audit, build, development proxy and
actual PostgreSQL/PCAP integration were verified during the React conversion.

JWTs stay in session memory. React escapes API text; live updates use fresh
single-use tickets, bounded reconnects and effect cleanup. Reference mock counts
and unsupported telemetry are replaced by actual backend data. Response remains
dry-run. Existing credentials are private in ignored `runtime/admin-login.txt`.
See [Sprint 3](../docs/SPRINT_3.md) for behavior and demonstration commands.
