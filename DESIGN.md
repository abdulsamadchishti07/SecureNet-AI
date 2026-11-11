# SecureNet AI dashboard design

Status: user selected the React SOC platform (`frontend/src/App.tsx`, adapted from
the supplied reference) on 2026-11-09. Product behavior is
specified in [the sprint plan](docs/SPRINT_3_TO_5_PLAN.md).

## 1. Visual Theme & Atmosphere

A focused security operations console following the supplied TSX: near-black slate
surfaces, emerald navigation, five metric cards, a three-panel chart row, incident
tables and a crimson live-feed panel. Explicit simulation labels remain visible.
Keywords: precise, calm,
technical, compact, accessible, responsive. English copy throughout.

Interaction tier: **L1**, CSS-only hover/focus feedback and a short entrance fade.
The dashboard prioritizes stable live data over decorative motion. No JavaScript
animation dependencies or external chart library. Implement with React,
TypeScript, Vite and Lucide, using the supplied TSX component as the basis.
FastAPI serves the compiled app from the same origin; Vite development proxies
HTTP and authenticated WebSocket traffic to the backend.

## 2. Color Palette & Roles

```css
:root {
  --bg: #0b0f17; --rail: #0d121c; --surface: #121824; --surface-alt: #172030;
  --surface-hover: #1b2739; --border: #1e2738; --border-hover: #3a4e6a;
  --text: #f8fafc; --text-secondary: #b1bdd0; --text-tertiary: #94a3b8;
  --accent: #10b981; --accent-hover: #34d399; --accent-ink: #05251b;
  --success: #4ade80; --error: #f87171; --warning: #fbbf24;
  --info: #60a5fa; --purple: #c4a3ff; --orange: #fb923c;
  --bg-rgb: 11, 15, 23; --accent-rgb: 16, 185, 129;
  --error-rgb: 248, 113, 113; --warning-rgb: 251, 191, 36;
  --info-rgb: 96, 165, 250; --shadow-rgb: 0, 0, 0;
}
```

All component colors use these tokens, including charts. Every status also has a
text label. Teal identifies navigation and primary actions; amber marks simulation
and pending work; red marks failures/threats, with text explaining their meaning.

## 3. Typography Rules

Use locally served Plus Jakarta Sans for headings/body, with `system-ui, sans-serif` fallback,
and locally served JetBrains Mono for endpoint values, with `ui-monospace, monospace`
fallback. Font sources, when available, are the Google Fonts families below; retain
their license files with any downloaded assets. The application must work offline.

```css
/* Source reference, not a runtime third-party dependency:
@import url('https://fonts.googleapis.com/css2?family=Plus+Jakarta+Sans:wght@400;500;600;700;800&family=JetBrains+Mono:wght@400;500&display=swap');
*/
:root {
  --font-body: 'Plus Jakarta Sans', system-ui, sans-serif;
  --font-mono: 'JetBrains Mono', ui-monospace, monospace;
}
```

| Role | Size | Weight | Line height |
| --- | --- | --- | --- |
| Page heading | 22px desktop / 21px mobile | 700 | 1.3 |
| Panel heading | 12–15px by available chart width | 700 | 1.5 |
| Body and forms | 12–13px | 400–600 | 1.6 |
| Labels and metadata | 9–12px by density | 500–700 | 1.6 |
| KPI value | 28px desktop / 25px mobile | 700 | 1.4 |
| Endpoint / identifier | 11px | 400 | 1.6 |

Use tabular numbers for metrics, restrained letter spacing for small uppercase
labels and no gradients, text shadows, novelty fonts or emoji icons.

## 4. Component Stylings

```css
.button, .nav-link, .tab { min-height: 44px; border-radius: 8px;
  border: 1px solid var(--border); background: var(--surface-alt);
  color: var(--text); padding: 10px 14px; font: inherit; cursor: pointer; }
.button:hover, .nav-link:hover, .tab:hover { background: var(--surface-hover);
  border-color: var(--border-hover); }
.button:active, .nav-link:active, .tab:active { transform: translateY(1px); }
.button:focus-visible, .nav-link:focus-visible, .tab:focus-visible,
input:focus-visible, select:focus-visible, a:focus-visible {
  outline: 2px solid var(--accent); outline-offset: 3px; }
.button:disabled, .tab:disabled { opacity: .55; cursor: not-allowed; transform: none; }
.button.primary { background: var(--accent); color: var(--accent-ink);
  border-color: var(--accent); font-weight: 700; }
.button.primary:hover { background: var(--accent-hover); }
.nav-link[aria-current='page'], .tab[aria-selected='true'] {
  color: var(--accent); border-color: var(--accent); }
.panel { background: var(--surface); border: 1px solid var(--border); border-radius: 12px; }
.panel:hover { border-color: var(--border-hover); }
.badge { display: inline-flex; align-items: center; gap: 6px; padding: 3px 8px;
  border: 1px solid var(--border); border-radius: 5px; font-size: 11px; font-weight: 700; }
.badge.warning { color: var(--warning); background: rgba(var(--warning-rgb), .09); }
.badge.danger { color: var(--error); background: rgba(var(--error-rgb), .09); }
input, select { min-height: 44px; min-width: 0; border-radius: 8px;
  border: 1px solid var(--border); background: var(--bg); color: var(--text);
  padding: 10px 12px; font: inherit; }
input:hover, select:hover { border-color: var(--border-hover); }
input:disabled, select:disabled { opacity: .55; cursor: not-allowed; }
a { color: var(--accent); text-underline-offset: 3px; }
a:hover { color: var(--accent-hover); }
a:active { opacity: .8; }
```

Tables use aligned columns, clear headers and row separators. Long model hashes
and IDs wrap or appear in a details view. Row controls use labelled buttons. Threat
distribution uses a donut and a full labelled count legend, never color alone.

Login is a full-page gate. User provisioning uses a native modal dialog with focus
restoration, visible field labels, inline validation and Escape to dismiss.
No focusable mutation controls are rendered for operators. Loading, empty, stale,
disconnected and error states use explicit copy rather than invented data.

## 5. Layout Principles

Desktop uses a 240px left navigation rail and flexible main column. Header contains
current account and live connection status. Five KPI cards sit above a three-panel
row (timeline, seven-class distribution, top sources), with recent alerts/protocol
data below and a 300px live-feed panel alongside. At narrower desktop widths the
feed stacks below. The response view contains lifecycle tabs and protected ranges.
Dashboard, alerts, traffic, logs, response, forensics, analytics and settings use
the same application shell, limited to supported API capabilities.

Spacing scale: 4, 8, 12, 16, 24 and 32px. Main padding 28px desktop / 16px mobile;
panel padding 20px; grid gap 16px. Use `minmax(0, 1fr)` in flexible grids. Keep
tables inside their own overflow container so the entire page never scrolls sideways.

## 6. Depth & Elevation

| Level | Treatment | Use |
| --- | --- | --- |
| Flat | Background token | Main workspace |
| Surface | 1px border, no shadow | Tables, charts and metrics |
| Elevated | 0 18px 60px rgba(var(--shadow-rgb), .35) | Login panel and modal |

Use a plain dimmed modal backdrop. Avoid moving blur effects and decorative glows.

## 7. Animation & Interaction

Tier L1. Native scrolling and no scroll-driven effects. Fade the authenticated
workspace in once; live updates do not move the whole page or steal focus.

```css
@keyframes enter { from { opacity: 0; transform: translateY(5px); }
  to { opacity: 1; transform: translateY(0); } }
.workspace { animation: enter 180ms ease-out both; }
.button, .nav-link, .tab { transition: background-color 140ms, border-color 140ms; }
@media (prefers-reduced-motion: reduce) {
  *, *::before, *::after { animation: none !important; transition: none !important;
    scroll-behavior: auto !important; }
}
```

Refresh controls expose busy state. HTTP errors are actionable text. Destructive
actions require an intentional click and remain pending until acknowledged. Live
updates are bounded, deduplicated and do not announce every row through a screen
reader. A compact status region announces connection changes.

## 8. Do's and Don'ts

- Do keep DRY-RUN / SIMULATED visible in the shell and response records.
- Do show zero actual firewall blocks separately from simulated state.
- Do give controls visible labels and keyboard focus.
- Do render API text using text nodes.
- Do distinguish pending acknowledgements from successful unblocks.
- Do keep JWTs only in memory and clear them on logout or expiry.
- Do show missing historical provenance as unavailable.
- Don't invent threat counts or pretend the sensor is connected because the API is.
- Don't show a kernel enforcement toggle in Sprint 3.
- Don't put JWTs in URLs, browser storage, assets or logs.
- Don't use untrusted HTML insertion for data or errors.
- Don't use animation, blinking or auto-scrolling that interrupts analysis.
- Don't require external fonts, image servers or CDNs for operation.
- Don't hide failed HTTP requests behind a success toast.
- Don't label built-in protected ranges as the sensor's complete configuration.

## 9. Responsive Behavior

| Width | Behavior |
| --- | --- |
| Above 1279px | Full navigation rail; five metrics; reference grid and side feed |
| 1101–1279px | Full rail; feed stacks below main panels |
| 701–1100px | Compact 76px icon rail; three metrics per row; two-column charts |
| Up to 700px | Single-column panels; two compact metrics per row; wrapping controls |

Minimum touch target 44×44px. Use native scrolling within wide tables, wrap endpoint
text in details, and ensure dialogs fit the viewport with internal scrolling.

```css
@media (max-width: 1100px) {
  .app-shell { grid-template-columns: 76px minmax(0, 1fr); }
  .metrics { grid-template-columns: repeat(3, minmax(0, 1fr)); }
}
@media (max-width: 700px) {
  .main { padding: 16px; }
  .app-shell { display: block; }
  .metrics { grid-template-columns: repeat(2, minmax(0, 1fr)); }
  .toolbar { flex-wrap: wrap; }
  dialog { width: calc(100% - 24px); max-height: calc(100dvh - 24px); overflow: auto; }
}
```

Reference audit: sidebar, five-card hierarchy, near-black palette, emerald state,
area chart, donut, top sources and crimson feed follow the provided TSX. Counts,
classes and controls use the actual backend contract. The detection table adds
flow/provenance columns, with protocol counts below for readability. Mock traffic,
unsupported payload/SHAP data and real-enforcement claims were not carried over.
Desktop/mobile images are in `reports/sprint3/`.
