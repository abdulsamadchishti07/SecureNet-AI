/** React/TypeScript adaptation of the supplied SecureNet platform component.
 * Mock datasets and simulated UI counters are replaced by authenticated API data.
 */
import { useEffect, useRef, useState } from "react";
import type { ReactNode } from "react";
import {
  ShieldCheck,
  Home,
  Bell,
  Activity,
  FileText,
  Ban,
  Search,
  BarChart2,
  Settings,
  LogOut,
  RefreshCw,
  Eye,
  X,
  ArrowRight,
} from "lucide-react";
import { CLASSES } from "./types";
import type { Analytics, BlockStatus, Detection, View } from "./types";
import { PAGE_SIZE, usePlatform } from "./usePlatform";
import type { Platform } from "./usePlatform";

const number = (value: number | undefined) =>
  value === undefined ? "—" : new Intl.NumberFormat().format(value);
const utc = (value: string | null | undefined) => {
  if (!value) return "Unavailable";
  const date = new Date(value);
  return Number.isFinite(date.getTime())
    ? date.toISOString().replace("T", " ").slice(0, 19)
    : "Unavailable";
};
const percent = (value: number) =>
  Number.isFinite(value) ? (value * 100).toFixed(1) + "%" : "Unavailable";
const protocol = (value: number) =>
  ({ 6: "TCP", 17: "UDP", 1: "ICMP" })[value] || `IP ${value}`;
const titles: Record<View, string> = {
  dashboard: "Dashboard",
  alerts: "Alerts",
  traffic: "Traffic Monitor",
  logs: "Detection Logs",
  response: "Blocked IPs",
  forensics: "Forensics",
  analytics: "Analytics",
  settings: "Settings",
};
const navigation = [
  { id: "dashboard", label: "Dashboard", Icon: Home },
  { id: "alerts", label: "Alerts", Icon: Bell },
  { id: "traffic", label: "Traffic Monitor", Icon: Activity },
  { id: "logs", label: "Logs", Icon: FileText },
  { id: "response", label: "Blocked IPs", Icon: Ban },
  { id: "forensics", label: "Forensics", Icon: Search },
  { id: "analytics", label: "Analytics", Icon: BarChart2 },
  { id: "settings", label: "Settings", Icon: Settings },
] as const;
const isClass = (value: string) =>
  (CLASSES as readonly string[]).includes(value);
function useDialog(open: boolean) {
  const ref = useRef<HTMLDialogElement>(null);
  useEffect(() => {
    if (open) ref.current?.showModal();
    else ref.current?.close();
  }, [open]);
  return ref;
}
const statuses: { value: BlockStatus; label: string }[] = [
  { value: "ACTIVE", label: "Active" },
  { value: "UNBLOCK_REQUESTED", label: "Requested" },
  { value: "EXPIRY_PENDING", label: "Expiry pending" },
  { value: "EXPIRED", label: "Expired" },
  { value: "UNBLOCKED", label: "Unblocked" },
  { value: "ROLLED_BACK", label: "Rolled back" },
];
function Badge({
  children,
  tone = "",
}: {
  children: ReactNode;
  tone?: string;
}) {
  return <span className={`badge ${tone}`}>{children || "Unavailable"}</span>;
}
function EmptyRow({
  columns,
  children,
}: {
  columns: number;
  children: ReactNode;
}) {
  return (
    <tr>
      <td colSpan={columns} className="empty-cell">
        {children}
      </td>
    </tr>
  );
}
function Brand() {
  return (
    <div className="brand">
      <span className="brand-mark">
        <ShieldCheck className="icon" />
      </span>
      <span>SecureNet AI</span>
    </div>
  );
}
function exportJson(value: unknown, filename: string) {
  const url = URL.createObjectURL(
    new Blob([JSON.stringify(value, null, 2)], { type: "application/json" }),
  );
  const anchor = document.createElement("a");
  anchor.href = url;
  anchor.download = filename;
  anchor.click();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}
function Clock() {
  const [now, setNow] = useState(() => new Date().toISOString().slice(11, 19));
  useEffect(() => {
    const timer = setInterval(
      () => setNow(new Date().toISOString().slice(11, 19)),
      1000,
    );
    return () => clearInterval(timer);
  }, []);
  return (
    <span id="clock" className="muted clock">
      {now} UTC
    </span>
  );
}

function Login({ platform }: { platform: Platform }) {
  const [busy, setBusy] = useState(false);
  return (
    <section
      id="login-screen"
      className="login-screen"
      aria-labelledby="login-title"
    >
      <div className="login-card panel">
        <Brand />
        <span className="eyebrow">THREAT DETECTION &amp; RESPONSE</span>
        <h1 id="login-title">
          Your network.
          <br />
          Your command center.
        </h1>
        <p className="muted">
          Sign in to review detections and manage simulated responses.
        </p>
        <form
          id="login-form"
          onSubmit={(event) => {
            event.preventDefault();
            const form = event.currentTarget,
              data = new FormData(form);
            setBusy(true);
            void platform
              .login(
                String(data.get("username") || ""),
                String(data.get("password") || ""),
              )
              .finally(() => {
                (
                  form.elements.namedItem("password") as HTMLInputElement
                ).value = "";
                setBusy(false);
              });
          }}
        >
          <label htmlFor="username">Username</label>
          <input
            id="username"
            name="username"
            autoComplete="username"
            maxLength={64}
            required
          />
          <label htmlFor="password">Password</label>
          <input
            id="password"
            name="password"
            type="password"
            autoComplete="current-password"
            required
          />
          <p id="login-error" className="error-message" role="alert">
            {platform.loginError}
          </p>
          <button className="button primary" type="submit" disabled={busy}>
            Sign in <ArrowRight className="icon" />
          </button>
        </form>
        <div className="login-footer">
          <span className="status-dot" /> Dry-run response · authenticated
          access
        </div>
      </div>
    </section>
  );
}

function Metrics({ platform }: { platform: Platform }) {
  const { stats, updatedAt } = platform.data;
  return (
    <div id="metrics" className="metrics">
      <article className="panel metric">
        <span>Total Events</span>
        <strong id="total-events">{number(stats?.total_events)}</strong>
        <small className="info">Persisted flows · all time</small>
      </article>
      <article className="panel metric">
        <span>Threats Detected</span>
        <strong id="total-attacks">{number(stats?.total_attacks)}</strong>
        <small className="danger-text">Non-benign flows · all time</small>
      </article>
      <article className="panel metric">
        <span>Simulated Blocks</span>
        <strong id="simulated-blocks">
          {number(stats?.active_simulated_blocks)}
        </strong>
        <small>
          <span id="actual-blocks">{number(stats?.active_blocked_ips)}</span>{" "}
          actual firewall blocks
        </small>
      </article>
      <article className="panel metric">
        <span>Pending Unblocks</span>
        <strong id="pending-unblocks">{number(stats?.pending_unblocks)}</strong>
        <small>Awaiting sensor acknowledgement</small>
      </article>
      <article className="panel metric">
        <span>API Status</span>
        <strong
          id="api-status"
          className={platform.unavailable ? "danger-text" : "success-text"}
        >
          {platform.unavailable ? "Unavailable" : stats ? "Ready" : "—"}
        </strong>
        <small id="updated-at">
          {updatedAt
            ? `Updated ${utc(updatedAt).slice(11)} UTC`
            : "No successful refresh yet"}
        </small>
      </article>
    </div>
  );
}
function Timeline({ analytics }: { analytics: Analytics | null }) {
  const buckets = analytics?.buckets || [],
    maximum = Math.max(1, ...buckets.map((bucket) => bucket.attacks));
  const points = buckets.map((bucket, i) => ({
    x: 30 + (i * 320) / Math.max(1, buckets.length - 1),
    y: 141 - (bucket.attacks / maximum) * 126,
  }));
  const path = points
    .map((point, i) => `${i ? "L" : "M"}${point.x},${point.y}`)
    .join(" ");
  return (
    <section className="panel chart-panel">
      <div className="panel-heading">
        <h2>Threats Over Time</h2>
        <Badge tone="danger">{number(analytics?.attack_flows)} flows</Badge>
      </div>
      <p className="panel-caption">
        Non-benign flows by observation time · UTC
      </p>
      <div
        id="timeline-chart"
        className="timeline-chart"
        role="img"
        aria-label={`${analytics?.attack_flows || 0} non-benign flows in the selected window`}
      >
        <svg viewBox="0 0 360 175" aria-hidden="true">
          {[0, 1, 2, 3].map((i) => (
            <g key={i}>
              <line
                x1={30}
                x2={350}
                y1={15 + i * 42}
                y2={15 + i * 42}
                className="chart-grid-line"
              />
              <text
                x={24}
                y={19 + i * 42}
                textAnchor="end"
                className="chart-label"
              >
                {Math.round(maximum * (1 - i / 3))}
              </text>
            </g>
          ))}
          {points.length > 0 && (
            <>
              <path d={`${path} L350,141 L30,141 Z`} className="threat-area" />
              <path d={path} className="threat-line" />
            </>
          )}
          {[0, 6, 12, 19].map((i) =>
            buckets[i] && points[i] ? (
              <text
                key={i}
                x={points[i].x}
                y={167}
                className="chart-label"
                textAnchor="middle"
              >
                {utc(buckets[i].start).slice(
                  (analytics?.window_minutes || 60) >= 1440 ? 5 : 11,
                  (analytics?.window_minutes || 60) >= 1440 ? 10 : 16,
                )}
              </text>
            ) : null,
          )}
        </svg>
      </div>
      <p id="timeline-summary" className="panel-caption">
        {analytics
          ? `${number(analytics.attack_flows)} threats / ${number(analytics.total_flows)} recorded flows in this window.`
          : "Waiting for event data."}
      </p>
    </section>
  );
}
function Distribution({
  counts,
  onFilter,
}: {
  counts: Record<string, number>;
  onFilter: (label: string) => void;
}) {
  const total = Object.values(counts).reduce((sum, value) => sum + value, 0),
    circumference = 2 * Math.PI * 56;
  const extra = Object.entries(counts)
    .filter(([key]) => !isClass(key))
    .reduce((sum, [, value]) => sum + value, 0);
  const labels: readonly string[] = extra
    ? [...CLASSES, "OTHER_SCOPES"]
    : CLASSES;
  let offset = 0;
  return (
    <section className="panel chart-panel">
      <div className="panel-heading">
        <h2>Threat Distribution</h2>
      </div>
      <p className="panel-caption">
        All persisted flows · seven unified classes
      </p>
      <div className="distribution-layout">
        <div
          id="donut-chart"
          className="donut-chart"
          role="img"
          aria-label="Seven-class flow distribution"
        >
          <svg viewBox="0 0 160 160">
            <circle cx={80} cy={80} r={56} className="donut-base" />
            {labels.map((label) => {
              const count =
                  label === "OTHER_SCOPES" ? extra : counts[label] || 0,
                length = total ? (count / total) * circumference : 0;
              const begin = offset;
              offset += length;
              return length > 0 ? (
                <circle
                  key={label}
                  cx={80}
                  cy={80}
                  r={56}
                  className={`donut-slice class-${label}`}
                  strokeDasharray={`${length} ${circumference}`}
                  strokeDashoffset={-begin}
                  transform="rotate(-90 80 80)"
                >
                  <title>
                    {label}: {count} flows
                  </title>
                </circle>
              ) : null;
            })}
            <text x={80} y={79} textAnchor="middle" className="donut-number">
              {number(total)}
            </text>
            <text x={80} y={97} textAnchor="middle" className="donut-label">
              flows · all time
            </text>
          </svg>
        </div>
        <div id="distribution-legend" className="distribution-legend">
          {labels.map((label) => (
            <button
              key={label}
              className="legend-button"
              onClick={() => onFilter(label === "OTHER_SCOPES" ? "" : label)}
            >
              <span className={`legend-dot class-${label}`} />
              <span>{label.replaceAll("_", " ")}</span>
              <strong>
                {number(label === "OTHER_SCOPES" ? extra : counts[label] || 0)}
              </strong>
            </button>
          ))}
        </div>
      </div>
    </section>
  );
}
function AnalyticsPanels({
  platform,
  onFilter,
  inspectSource,
}: {
  platform: Platform;
  onFilter: (label: string) => void;
  inspectSource: (ip: string) => void;
}) {
  const sources = platform.data.analytics?.top_sources || [];
  return (
    <div id="analytics-section">
      <div className="section-toolbar">
        <span className="eyebrow">DETECTION OVERVIEW</span>
        <label className="inline-label" htmlFor="time-window">
          Chart window{" "}
          <select
            id="time-window"
            value={platform.query.minutes}
            onChange={(event) =>
              platform.updateQuery({ minutes: Number(event.target.value) })
            }
          >
            <option value={15}>Last 15 minutes</option>
            <option value={60}>Last 1 hour</option>
            <option value={1440}>Last 24 hours</option>
            <option value={10080}>Last 7 days</option>
          </select>
        </label>
      </div>
      <div className="chart-grid">
        <Timeline analytics={platform.data.analytics} />
        <Distribution
          counts={platform.data.stats?.threat_distribution || {}}
          onFilter={onFilter}
        />
        <section className="panel chart-panel">
          <div className="panel-heading">
            <h2>Top Threat Sources</h2>
          </div>
          <p className="panel-caption">
            Non-benign flow counts · selected window
          </p>
          <div className="table-wrap">
            <table className="compact-table">
              <thead>
                <tr>
                  <th>IP address</th>
                  <th>Flows</th>
                  <th>Inspect</th>
                </tr>
              </thead>
              <tbody id="source-rows">
                {sources.length ? (
                  sources.map((source) => (
                    <tr key={source.ip}>
                      <td className="mono">{source.ip}</td>
                      <td>{number(source.count)}</td>
                      <td>
                        <button
                          className="button icon-button"
                          aria-label={`Inspect source ${source.ip}`}
                          onClick={() => inspectSource(source.ip)}
                        >
                          <Search className="icon" />
                        </button>
                      </td>
                    </tr>
                  ))
                ) : (
                  <EmptyRow columns={3}>No threats in this window.</EmptyRow>
                )}
              </tbody>
            </table>
          </div>
        </section>
      </div>
    </div>
  );
}

function Alerts({
  platform,
  view,
  inspect,
}: {
  platform: Platform;
  view: View;
  inspect: (event: Detection) => void;
}) {
  const { query, data } = platform;
  return (
    <section id="alerts-section" className="panel alerts-panel">
      <div className="panel-heading">
        <div>
          <h2 id="alerts-title">
            {view === "logs"
              ? "Detection Decision Log"
              : view === "forensics"
                ? "Stored Flow Forensics"
                : "Recent Alerts"}
          </h2>
          <p className="panel-caption">
            Stored detections, including benign flows. Inspect a row for
            provenance.
          </p>
        </div>
        <button
          id="export-alerts"
          className="button small"
          onClick={() =>
            exportJson(
              { scope: "current filtered page", events: data.alerts },
              "securenet-alert-page.json",
            )
          }
        >
          Export page
        </button>
      </div>
      <form
        id="filter-form"
        key={`${query.label}:${query.confidence}`}
        className="filter-form"
        onSubmit={(event) => {
          event.preventDefault();
          const form = new FormData(event.currentTarget);
          platform.updateQuery({
            label: String(form.get("label") || ""),
            confidence: String(form.get("confidence") || "0"),
            alertOffset: 0,
          });
        }}
      >
        <div>
          <label htmlFor="label-filter">Threat class</label>
          <select id="label-filter" name="label" defaultValue={query.label}>
            <option value="">All classes</option>
            {CLASSES.map((value) => (
              <option key={value}>{value}</option>
            ))}
          </select>
        </div>
        <div>
          <label htmlFor="confidence-filter">Minimum confidence</label>
          <input
            id="confidence-filter"
            name="confidence"
            type="number"
            min={0}
            max={1}
            step="0.01"
            defaultValue={query.confidence}
          />
        </div>
        <button className="button" type="submit">
          Apply filters
        </button>
        <button
          id="reset-filters"
          className="button"
          type="reset"
          onClick={() =>
            platform.updateQuery({ label: "", confidence: "0", alertOffset: 0 })
          }
        >
          Reset
        </button>
      </form>
      <div
        className="table-wrap"
        tabIndex={0}
        aria-label="Detection table, scroll horizontally if needed"
      >
        <table>
          <thead>
            <tr>
              <th>Observed · UTC</th>
              <th>Threat class</th>
              <th>Source → destination</th>
              <th>Confidence</th>
              <th>Policy</th>
              <th>Sensor / model</th>
              <th>Details</th>
            </tr>
          </thead>
          <tbody id="alert-rows">
            {data.alerts.length ? (
              data.alerts.map((event) => (
                <tr key={event.event_id}>
                  <td className="mono nowrap">{utc(event.observed_at)}</td>
                  <td>
                    <Badge
                      tone={event.label === "BENIGN" ? "success" : "danger"}
                    >
                      {event.label}
                    </Badge>
                  </td>
                  <td className="endpoint-cell mono">
                    {event.src_ip}:{event.src_port}
                    <span className="subline">
                      → {event.dst_ip}:{event.dst_port} ·{" "}
                      {protocol(event.protocol)}
                    </span>
                  </td>
                  <td className="mono">{percent(event.confidence)}</td>
                  <td>
                    <Badge
                      tone={
                        event.decision_action === "candidate" ? "warning" : ""
                      }
                    >
                      {event.decision_action}
                    </Badge>
                  </td>
                  <td className="identity-cell mono">
                    {event.sensor_id || "Unavailable"}
                    <span className="subline">
                      {event.model_run || "Unavailable"}
                    </span>
                  </td>
                  <td>
                    <button
                      className="button icon-button"
                      aria-label="Inspect event"
                      onClick={() => inspect(event)}
                    >
                      <Eye className="icon" />
                    </button>
                  </td>
                </tr>
              ))
            ) : (
              <EmptyRow columns={7}>
                No detections match these filters.
              </EmptyRow>
            )}
          </tbody>
        </table>
      </div>
      <div className="pagination">
        <span id="alert-page-label" className="muted">
          {data.alerts.length
            ? `Showing ${query.alertOffset + 1}–${query.alertOffset + data.alerts.length} · newest first`
            : "No matching events"}
        </span>
        <div>
          <button
            id="alerts-prev"
            className="button small"
            disabled={!query.alertOffset}
            onClick={() =>
              platform.updateQuery({
                alertOffset: Math.max(0, query.alertOffset - PAGE_SIZE),
              })
            }
          >
            Previous
          </button>
          <button
            id="alerts-next"
            className="button small"
            disabled={data.alerts.length < PAGE_SIZE}
            onClick={() =>
              platform.updateQuery({
                alertOffset: query.alertOffset + PAGE_SIZE,
              })
            }
          >
            Next
          </button>
        </div>
      </div>
    </section>
  );
}
function Protocols({ analytics }: { analytics: Analytics | null }) {
  return (
    <section id="protocol-section" className="panel">
      <div className="panel-heading">
        <div>
          <h2>Traffic by Protocol</h2>
          <p className="panel-caption">
            Recorded flows in the chart window · IP protocol numbers
          </p>
        </div>
        <Activity className="icon info" />
      </div>
      <div id="protocol-bars" className="protocol-bars">
        {analytics?.protocols.length ? (
          analytics.protocols.map((entry) => (
            <div key={entry.protocol} className="protocol-line">
              <span className="mono">{protocol(entry.protocol)}</span>
              <meter
                max={Math.max(1, analytics.total_flows)}
                value={entry.count}
                aria-label={`${protocol(entry.protocol)}: ${entry.count} flows`}
              />
              <small>
                {number(entry.count)} ·{" "}
                {Math.round(
                  (entry.count / Math.max(1, analytics.total_flows)) * 100,
                )}
                %
              </small>
            </div>
          ))
        ) : (
          <p className="muted">No recorded flows in this window.</p>
        )}
      </div>
    </section>
  );
}
function Response({ platform }: { platform: Platform }) {
  const { data, query, user } = platform;
  const [pending, setPending] = useState<string | null>(null);
  return (
    <section id="response-section" className="panel">
      <div className="panel-heading">
        <div>
          <h2>Response Lifecycle</h2>
          <p className="panel-caption">
            Default mode is dry-run simulation; isolated enforcement uses the
            privileged nftables helper. Status changes require sensor
            acknowledgement.
          </p>
        </div>
        <Badge
          tone={data.stats?.response_mode === "enforced" ? "danger" : "warning"}
        >
          {data.stats?.response_mode === "enforced"
            ? "ENFORCED"
            : data.stats?.response_mode === "mixed"
              ? "MIXED"
              : "DRY-RUN"}
        </Badge>
      </div>
      <div
        id="block-tabs"
        className="tabs"
        role="tablist"
        aria-label="Block status"
      >
        {statuses.map((status) => (
          <button
            key={status.value}
            className="tab"
            role="tab"
            aria-selected={query.blockStatus === status.value}
            onClick={() =>
              platform.updateQuery({
                blockStatus: status.value,
                blockOffset: 0,
              })
            }
          >
            {status.label}
          </button>
        ))}
      </div>
      <p className="panel-caption">
        A disconnected sensor leaves commands pending. Enforced blocks roll back
        on sensor shutdown or helper lease loss.
      </p>
      <div
        className="table-wrap"
        tabIndex={0}
        aria-label="Response table, scroll horizontally if needed"
      >
        <table>
          <thead>
            <tr>
              <th>IP / block identity</th>
              <th>Threat / sensor</th>
              <th>Status</th>
              <th>Blocked · UTC</th>
              <th>Expiry · UTC</th>
              <th>Proposed command</th>
              <th>Control</th>
            </tr>
          </thead>
          <tbody id="block-rows">
            {data.blocks.length ? (
              data.blocks.map((block) => (
                <tr key={block.id}>
                  <td className="identity-cell mono">
                    {block.ip}
                    <span className="subline">
                      {block.block_id || "Legacy · no block UUID"}
                    </span>
                  </td>
                  <td className="mono">
                    {block.threat}
                    <span className="subline">
                      {block.sensor_id || "Ownership unavailable"} ·{" "}
                      {block.mode}
                    </span>
                  </td>
                  <td>
                    <Badge
                      tone={
                        ["EXPIRED", "UNBLOCKED", "ROLLED_BACK"].includes(
                          block.status,
                        )
                          ? "success"
                          : block.mode === "enforced"
                            ? "danger"
                            : "warning"
                      }
                    >
                      {block.status}
                    </Badge>
                  </td>
                  <td className="mono nowrap">{utc(block.blocked_at)}</td>
                  <td className="mono nowrap">{utc(block.unblock_at)}</td>
                  <td className="mono command-cell">
                    {block.command?.join(" ") || "Unavailable"}
                  </td>
                  <td>
                    {user?.is_admin &&
                    ["ACTIVE", "EXPIRY_PENDING"].includes(block.status) &&
                    block.block_id &&
                    block.sensor_id ? (
                      <button
                        className="button small danger"
                        disabled={pending === block.block_id}
                        onClick={() => {
                          setPending(block.block_id);
                          void platform
                            .unblock(block)
                            .finally(() => setPending(null));
                        }}
                      >
                        Request unblock
                      </button>
                    ) : (
                      <span className="muted">
                        {block.status === "UNBLOCK_REQUESTED"
                          ? "Awaiting sensor"
                          : "—"}
                      </span>
                    )}
                  </td>
                </tr>
              ))
            ) : (
              <EmptyRow columns={7}>
                No simulated blocks with this status.
              </EmptyRow>
            )}
          </tbody>
        </table>
      </div>
      <div className="pagination">
        <span id="block-page-label" className="muted">
          {data.blocks.length
            ? `Showing ${query.blockOffset + 1}–${query.blockOffset + data.blocks.length}`
            : "No records"}
        </span>
        <div>
          <button
            id="blocks-prev"
            className="button small"
            disabled={!query.blockOffset}
            onClick={() =>
              platform.updateQuery({
                blockOffset: Math.max(0, query.blockOffset - PAGE_SIZE),
              })
            }
          >
            Previous
          </button>
          <button
            id="blocks-next"
            className="button small"
            disabled={data.blocks.length < PAGE_SIZE}
            onClick={() =>
              platform.updateQuery({
                blockOffset: query.blockOffset + PAGE_SIZE,
              })
            }
          >
            Next
          </button>
        </div>
      </div>
      <div className="protected-ranges">
        <h3>Built-in protected ranges</h3>
        <p className="muted">
          Default exclusions only. Additional sensor protection settings are not
          reported by this endpoint.
        </p>
        <div id="protected-cidrs" className="cidr-list">
          {data.cidrs.map((range) => (
            <code key={range}>{range}</code>
          ))}
        </div>
      </div>
    </section>
  );
}
function LiveFeed({
  events,
  inspect,
  showAlerts,
}: {
  events: Detection[];
  inspect: (event: Detection) => void;
  showAlerts: () => void;
}) {
  const [threatsOnly, setThreatsOnly] = useState(false),
    filtered = events.filter(
      (event) => !threatsOnly || event.label !== "BENIGN",
    );
  return (
    <aside id="feed-panel" className="panel feed-panel">
      <div className="feed-header">
        <h2>Live Alerts Feed</h2>
        <Bell className="icon" />
      </div>
      <div className="feed-controls">
        <button
          id="feed-all"
          className="tab"
          aria-pressed={!threatsOnly}
          onClick={() => setThreatsOnly(false)}
        >
          All events
        </button>
        <button
          id="feed-attacks"
          className="tab"
          aria-pressed={threatsOnly}
          onClick={() => setThreatsOnly(true)}
        >
          Threats only
        </button>
      </div>
      <p className="feed-caption">
        Latest stored detections · live API updates
      </p>
      <div id="live-feed" className="live-feed">
        {filtered.length ? (
          filtered.map((event) => (
            <button
              key={event.event_id}
              className="feed-item"
              aria-label={`Inspect ${event.label} event from ${event.src_ip}`}
              onClick={() => inspect(event)}
            >
              <div className="feed-item-title">
                <span
                  className={`legend-dot class-${isClass(event.label) ? event.label : "OTHER"}`}
                />
                <span>
                  {event.label} from {event.src_ip}
                </span>
              </div>
              <div className="feed-item-meta">
                <Badge tone={event.label === "BENIGN" ? "success" : "danger"}>
                  {event.decision_action}
                </Badge>
                <span className="mono">{utc(event.observed_at).slice(11)}</span>
              </div>
            </button>
          ))
        ) : (
          <p className="empty-cell">No stored events to display.</p>
        )}
      </div>
      <div className="feed-footer">
        <button
          id="view-alerts"
          className="button feed-button"
          onClick={showAlerts}
        >
          View All Alerts <ArrowRight className="icon" />
        </button>
        <p>
          Flow verdicts are experimental.
          <br />
          WEB_ATTACK remains alert-only.
        </p>
      </div>
    </aside>
  );
}

function EventDialog({
  event,
  close,
}: {
  event: Detection | null;
  close: () => void;
}) {
  const ref = useDialog(Boolean(event));
  const fields = event
    ? {
        "Event ID": event.event_id,
        "Observed · UTC": utc(event.observed_at),
        "Threat class": event.label,
        Confidence: percent(event.confidence),
        Source: `${event.src_ip}:${event.src_port}`,
        Destination: `${event.dst_ip}:${event.dst_port}`,
        Protocol: protocol(event.protocol),
        "Capture source": event.source,
        Sensor: event.sensor_id,
        "Model scope": event.model_scope,
        "Model run": event.model_run,
        "Model SHA-256": event.model_sha256,
        "Policy action": event.decision_action,
        "Policy reason": event.decision_reason,
      }
    : {};
  return (
    <dialog
      ref={ref}
      id="event-dialog"
      className="event-dialog"
      aria-labelledby="event-title"
      onClose={close}
      onCancel={close}
    >
      <div className="dialog-heading">
        <div>
          <span className="eyebrow">FLOW FORENSICS</span>
          <h2 id="event-title">Event Details</h2>
        </div>
        <button
          className="button icon-button"
          aria-label="Close event details"
          onClick={close}
        >
          <X className="icon" />
        </button>
      </div>
      <dl id="event-details" className="detail-grid">
        {Object.entries(fields).map(([name, value]) => (
          <div className="detail-pair" key={name}>
            <dt>{name}</dt>
            <dd>{value ?? "Unavailable"}</dd>
          </div>
        ))}
      </dl>
      <p className="muted">
        Recorded flow metadata and model output. Payloads, GeoIP and feature
        explanations are not collected here.
      </p>
      <div className="dialog-actions">
        <button
          id="export-event"
          className="button"
          onClick={() => event && exportJson(event, "securenet-event.json")}
        >
          Export event JSON
        </button>
        <button className="button" onClick={close}>
          Done
        </button>
      </div>
    </dialog>
  );
}
function UserDialog({
  open,
  close,
  platform,
}: {
  open: boolean;
  close: () => void;
  platform: Platform;
}) {
  const ref = useDialog(open),
    [error, setError] = useState(""),
    [busy, setBusy] = useState(false);
  useEffect(() => setError(""), [open]);
  return (
    <dialog
      ref={ref}
      id="user-dialog"
      aria-labelledby="user-title"
      onClose={close}
      onCancel={close}
    >
      <div className="dialog-heading">
        <div>
          <span className="eyebrow">ADMINISTRATION</span>
          <h2 id="user-title">Add a team member</h2>
        </div>
        <button
          className="button icon-button"
          aria-label="Close user form"
          onClick={close}
        >
          <X className="icon" />
        </button>
      </div>
      <form
        id="user-form"
        key={String(open)}
        onSubmit={(event) => {
          event.preventDefault();
          const form = new FormData(event.currentTarget),
            password = String(form.get("password") || "");
          setError("");
          if (
            [...password].length < 12 ||
            new TextEncoder().encode(password).length > 72
          ) {
            setError("Use at least 12 characters and at most 72 UTF-8 bytes.");
            return;
          }
          setBusy(true);
          void platform
            .provision({
              username: String(form.get("username") || ""),
              email: String(form.get("email") || ""),
              password,
              is_admin: form.has("is_admin"),
            })
            .then(close)
            .catch((reason) =>
              setError(
                reason instanceof Error ? reason.message : "Request failed.",
              ),
            )
            .finally(() => setBusy(false));
        }}
      >
        <label htmlFor="new-username">New username</label>
        <input
          id="new-username"
          name="username"
          required
          minLength={3}
          maxLength={64}
          pattern="[A-Za-z0-9_.-]+"
          autoComplete="off"
        />
        <label htmlFor="new-email">Email</label>
        <input
          id="new-email"
          name="email"
          type="email"
          required
          maxLength={128}
          autoComplete="off"
        />
        <label htmlFor="new-password">New password</label>
        <input
          id="new-password"
          name="password"
          type="password"
          required
          minLength={12}
          autoComplete="new-password"
        />
        <p className="panel-caption">
          At least 12 characters; at most 72 UTF-8 bytes.
        </p>
        <label className="checkbox-label">
          <input id="new-admin" name="is_admin" type="checkbox" /> Administrator
          access
        </label>
        <p id="user-error" className="error-message" role="alert">
          {error}
        </p>
        <div className="dialog-actions">
          <button type="button" className="button" onClick={close}>
            Cancel
          </button>
          <button className="button primary" type="submit" disabled={busy}>
            Create account
          </button>
        </div>
      </form>
    </dialog>
  );
}
function SettingsPanel({
  platform,
  addUser,
}: {
  platform: Platform;
  addUser: () => void;
}) {
  return (
    <section id="settings-section" className="panel">
      <div className="panel-heading">
        <h2>Workspace Settings</h2>
        <Badge tone="warning">SIMULATION</Badge>
      </div>
      <dl id="account-details" className="detail-grid">
        {Object.entries({
          Username: platform.user?.username,
          Email: platform.user?.email,
          Role: platform.user?.is_admin ? "Administrator" : "Operator",
          "Session storage": "5m access token · 15d sliding refresh token",
        }).map(([name, value]) => (
          <div className="detail-pair" key={name}>
            <dt>{name}</dt>
            <dd>{value}</dd>
          </div>
        ))}
      </dl>
      <div className="settings-note">
        <h3>Response controls</h3>
        <p>
          Response policy runs in the sensor process (dry-run by default;
          optional nftables enforcement via the privilege-separated helper).
          Email/SMS delivery, payload inspection and host resource telemetry are
          not enabled.
        </p>
        <p>
          Dashboard connection status describes the API alert stream. It does
          not establish that a capture sensor is online.
        </p>
      </div>
      {platform.user?.is_admin && (
        <button className="button small" onClick={addUser}>
          Provision account
        </button>
      )}
    </section>
  );
}

export default function SecureNetPlatform() {
  const platform = usePlatform(),
    [view, setView] = useState<View>("dashboard");
  const [selectedEvent, setSelectedEvent] = useState<Detection | null>(null),
    [addingUser, setAddingUser] = useState(false);
  const user = platform.user,
    data = platform.data;
  useEffect(() => {
    if (!user) {
      setView("dashboard");
      setSelectedEvent(null);
      setAddingUser(false);
    }
  }, [user]);
  if (!user) return <Login platform={platform} />;
  const showFeed = view !== "response" && view !== "settings";
  const showAlerts = [
    "dashboard",
    "alerts",
    "traffic",
    "logs",
    "forensics",
  ].includes(view);
  const filter = (label: string) => {
    platform.updateQuery({ label, alertOffset: 0 });
    setView("alerts");
  };
  const inspectSource = (ip: string) => {
    const event = data.feed.find((item) => item.src_ip === ip);
    if (event) setSelectedEvent(event);
    else {
      setView("forensics");
      platform.announce(
        `Use the detection table to inspect stored flow metadata for ${ip}.`,
      );
    }
  };
  return (
    <div id="workspace" className="workspace app-shell">
      <aside className="sidebar">
        <Brand />
        <span className="nav-caption">WORKSPACE</span>
        <nav id="navigation" aria-label="Main navigation">
          {navigation.map(({ id, label, Icon }) => (
            <button
              key={id}
              className="nav-link"
              data-view={id}
              aria-label={id === "response" ? "Response" : titles[id]}
              aria-current={view === id ? "page" : undefined}
              onClick={() => setView(id)}
            >
              <Icon className="icon" />
              <span>{label}</span>
              {(id === "alerts" || id === "response") && (
                <span
                  id={id === "alerts" ? "nav-alert-count" : "nav-block-count"}
                  className="nav-count"
                >
                  {number(
                    id === "alerts"
                      ? data.stats?.total_attacks
                      : data.stats
                        ? data.stats.active_simulated_blocks +
                          data.stats.active_blocked_ips
                        : undefined,
                  )}
                </span>
              )}
            </button>
          ))}
        </nav>
        <div className="sidebar-bottom">
          <button
            id="sign-out"
            className="nav-link"
            aria-label="Sign out"
            onClick={() => platform.logout()}
          >
            <LogOut className="icon" />
            <span>Sign out</span>
          </button>
          <div className="profile">
            <span id="avatar" className="avatar">
              {user.username[0]?.toUpperCase()}
            </span>
            <div>
              <strong id="profile-name">{user.username}</strong>
              <span id="profile-email" className="muted">
                {user.email}
              </span>
            </div>
          </div>
        </div>
      </aside>
      <div className="main-shell">
        <header className="topbar">
          <div className="page-heading">
            <h1 id="page-title">{titles[view]}</h1>
            <Badge
              tone={
                data.stats?.response_mode === "enforced" ? "danger" : "warning"
              }
            >
              {data.stats?.response_mode === "enforced"
                ? "ENFORCED · NFTABLES"
                : data.stats?.response_mode === "mixed"
                  ? "MIXED · SIMULATED + ENFORCED"
                  : "DRY-RUN · SIMULATED"}
            </Badge>
          </div>
          <div className="header-controls">
            <span className="connection" role="status">
              <span
                id="connection-dot"
                className={`status-dot ${platform.connection === "Connected" ? "" : "offline"}`}
              />
              <span id="connection-status">{platform.connection}</span>
            </span>
            <Clock />
            <button
              id="refresh"
              className="button small"
              aria-label="Refresh"
              disabled={platform.busy}
              aria-busy={platform.busy}
              onClick={platform.refresh}
            >
              <RefreshCw className="icon" />
              <span>Refresh</span>
            </button>
            {user.is_admin && (
              <button
                className="button small"
                onClick={() => setAddingUser(true)}
              >
                Add user
              </button>
            )}
            <Badge>{user.is_admin ? "ADMIN" : "OPERATOR"}</Badge>
          </div>
        </header>
        <main className="main">
          <div className="workspace-intro">
            <div>
              <span className="eyebrow">SECURITY OPERATIONS</span>
              <p id="view-description">
                {view === "logs"
                  ? "Stored detection decisions; this is not a complete firewall audit log."
                  : view === "traffic"
                    ? "Recorded flow metadata. Packet capture status and live bandwidth are not reported."
                    : "A clear view of your network’s detection and response activity."}
              </p>
            </div>
            <span className="scope-note">
              Flow-level detection · experimental model
            </span>
          </div>
          <p
            id="notice"
            className={`notice ${platform.notice.error ? "error" : ""}`}
            role="status"
            hidden={!platform.notice.message}
          >
            {platform.notice.message}
          </p>
          <Metrics platform={platform} />
          <div
            id="dashboard-layout"
            className={`dashboard-layout ${showFeed ? "" : "single-column"}`}
          >
            <div className="center-column">
              {(view === "dashboard" || view === "analytics") && (
                <AnalyticsPanels
                  platform={platform}
                  onFilter={filter}
                  inspectSource={inspectSource}
                />
              )}
              {showAlerts && (
                <Alerts
                  platform={platform}
                  view={view}
                  inspect={setSelectedEvent}
                />
              )}
              {["dashboard", "traffic", "analytics"].includes(view) && (
                <Protocols analytics={data.analytics} />
              )}
              {view === "response" && <Response platform={platform} />}
              {view === "settings" && (
                <SettingsPanel
                  platform={platform}
                  addUser={() => setAddingUser(true)}
                />
              )}
            </div>
            {showFeed && (
              <LiveFeed
                events={data.feed}
                inspect={setSelectedEvent}
                showAlerts={() => setView("alerts")}
              />
            )}
          </div>
          <footer className="workspace-footer">
            <span>SecureNet AI · Threat Detection &amp; Response</span>
            <span>Dry-run response · no kernel enforcement</span>
          </footer>
        </main>
      </div>
      <EventDialog event={selectedEvent} close={() => setSelectedEvent(null)} />
      {user.is_admin && (
        <UserDialog
          open={addingUser}
          close={() => setAddingUser(false)}
          platform={platform}
        />
      )}
    </div>
  );
}
