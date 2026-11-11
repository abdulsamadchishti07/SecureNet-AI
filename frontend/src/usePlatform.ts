import { useEffect, useRef, useState } from "react";
import { ApiError, request } from "./api";
import type { Session } from "./api";
import type {
  Analytics,
  Block,
  DashboardData,
  Detection,
  NewUser,
  Notice,
  Query,
  Stats,
  User,
} from "./types";

export const PAGE_SIZE = 25;
const REFRESH_KEY = "securenet_refresh_token";
const getRefresh = () => {
  try {
    return localStorage.getItem(REFRESH_KEY);
  } catch {
    return null;
  }
};
const setRefresh = (token: string | null) => {
  try {
    if (token) localStorage.setItem(REFRESH_KEY, token);
    else localStorage.removeItem(REFRESH_KEY);
  } catch {}
};
const initialQuery: Query = {
  label: "",
  confidence: "0",
  alertOffset: 0,
  blockOffset: 0,
  blockStatus: "ACTIVE",
  minutes: 60,
};
const emptyData = (): DashboardData => ({
  stats: null,
  analytics: null,
  alerts: [],
  blocks: [],
  feed: [],
  cidrs: [],
  updatedAt: null,
});
const mergeFeed = (old: Detection[], incoming: Detection[]) =>
  [
    ...new Map(
      [...old, ...incoming].map((event) => [event.event_id, event]),
    ).values(),
  ]
    .sort(
      (a, b) =>
        Date.parse(b.observed_at) - Date.parse(a.observed_at) || b.id - a.id,
    )
    .slice(0, 8);

export function usePlatform() {
  const [session, setSession] = useState<Session | null>(null);
  const sessionRef = useRef<Session | null>(null);
  const [data, setData] = useState<DashboardData>(emptyData);
  const [query, setQuery] = useState<Query>(initialQuery);
  const queryRef = useRef(query);
  const [notice, setNotice] = useState<Notice>({ message: "", error: false });
  const [loginError, setLoginError] = useState("");
  const [connection, setConnection] = useState("Disconnected");
  const [busy, setBusy] = useState(false);
  const [unavailable, setUnavailable] = useState(false);
  const [reconnectKey, setReconnectKey] = useState(0);
  const [expiresAt, setExpiresAt] = useState(0);
  const seq = useRef<[number, number, number, number]>([0, 0, 0, 0]);
  const pendingCommand = useRef<string | null>(null);
  const refreshing = useRef<{ client: Session; promise: Promise<void> } | null>(
    null,
  );
  const refreshingAuth = useRef<Promise<Session | null> | null>(null);
  const retried401 = useRef(false);
  const active = (client: Session) =>
    sessionRef.current === client && !client.controller.signal.aborted;
  const announce = (message: string, error = false) =>
    setNotice({ message, error });

  const logout = (reason = "") => {
    const refreshToken = getRefresh();
    setRefresh(null);
    if (refreshToken)
      void request("/api/auth/logout", null, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ refresh_token: refreshToken }),
      }).catch(() => {});
    sessionRef.current?.controller.abort();
    sessionRef.current = null;
    setSession(null);
    setExpiresAt(0);
    setData(emptyData());
    setLoginError(reason);
    setConnection("Disconnected");
    setBusy(false);
    setUnavailable(false);
    setNotice({ message: "", error: false });
    queryRef.current = initialQuery;
    setQuery(initialQuery);
    pendingCommand.current = null;
    refreshing.current = null;
    retried401.current = false;
  };
  const refreshAccess = (): Promise<Session | null> => {
    if (refreshingAuth.current) return refreshingAuth.current;
    const refreshToken = getRefresh();
    if (!refreshToken) {
      logout("Your session expired. Please sign in again.");
      return Promise.resolve(null);
    }
    const job = (async () => {
      try {
        const result = await request<{
          access_token: string;
          refresh_token: string;
          expires_in: number;
        }>("/api/auth/refresh", null, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ refresh_token: refreshToken }),
        });
        const existing = sessionRef.current;
        const user =
          existing?.user ??
          (await request<User>("/api/auth/me", null, {
            headers: { Authorization: `Bearer ${result.access_token}` },
          }));
        setRefresh(result.refresh_token);
        const exp = Date.now() + result.expires_in * 1000;
        if (existing && !existing.controller.signal.aborted) {
          existing.token = result.access_token;
          existing.expiresAt = exp;
          setExpiresAt(exp);
          return existing;
        }
        const client: Session = {
          token: result.access_token,
          user,
          expiresAt: exp,
          controller: new AbortController(),
        };
        sessionRef.current = client;
        setSession(client);
        setExpiresAt(exp);
        return client;
      } catch {
        logout("Your session expired. Please sign in again.");
        return null;
      } finally {
        refreshingAuth.current = null;
      }
    })();
    refreshingAuth.current = job;
    return job;
  };
  const fail = (error: unknown, client: Session) => {
    if (!active(client)) return;
    if (error instanceof ApiError && error.status === 401) {
      if (!retried401.current && getRefresh()) {
        retried401.current = true;
        void refreshAccess().then((ok) => {
          if (ok) void refreshAll();
        });
      } else {
        logout("Your session expired. Please sign in again.");
      }
    } else
      announce(
        error instanceof Error
          ? error.message
          : "Request failed. Please retry.",
        true,
      );
  };
  const login = async (username: string, password: string) => {
    setLoginError("");
    try {
      const {
        access_token: token,
        refresh_token,
        expires_in,
      } = await request<{
        access_token: string;
        refresh_token: string;
        expires_in: number;
      }>("/api/auth/login", null, {
        method: "POST",
        body: new URLSearchParams({ username, password }),
      });
      const user = await request<User>("/api/auth/me", null, {
        headers: { Authorization: `Bearer ${token}` },
      });
      setRefresh(refresh_token);
      retried401.current = false;
      const client: Session = {
        token,
        user,
        expiresAt: Date.now() + expires_in * 1000,
        controller: new AbortController(),
      };
      sessionRef.current = client;
      setSession(client);
      setExpiresAt(client.expiresAt);
      setData(emptyData());
    } catch (error) {
      setLoginError(
        error instanceof Error ? error.message : "Unable to sign in.",
      );
    }
  };

  const loadStats = async (client: Session) => {
    const id = ++seq.current[0];
    const stats = await request<Stats>("/api/stats", client);
    if (!active(client) || id !== seq.current[0]) return;
    retried401.current = false;
    setData((old) => ({ ...old, stats, updatedAt: new Date().toISOString() }));
    if (pendingCommand.current && stats.pending_unblocks === 0) {
      pendingCommand.current = null;
      announce(
        "Sensor acknowledgement received. The simulated block is absent.",
      );
    }
  };
  const loadAnalytics = async (client: Session) => {
    const id = ++seq.current[1];
    const analytics = await request<Analytics>(
      `/api/analytics?minutes=${queryRef.current.minutes}`,
      client,
    );
    if (active(client) && id === seq.current[1])
      setData((old) => ({ ...old, analytics }));
  };
  const loadAlerts = async (client: Session) => {
    const id = ++seq.current[2],
      q = queryRef.current;
    const params = new URLSearchParams({
      skip: String(q.alertOffset),
      limit: String(PAGE_SIZE),
    });
    if (q.label) params.set("label", q.label);
    if (q.confidence) params.set("min_confidence", q.confidence);
    const alerts = await request<Detection[]>("/api/alerts?" + params, client);
    if (active(client) && id === seq.current[2])
      setData((old) => ({ ...old, alerts }));
  };
  const loadBlocks = async (client: Session) => {
    const id = ++seq.current[3],
      q = queryRef.current;
    const params = new URLSearchParams({
      status: q.blockStatus,
      skip: String(q.blockOffset),
      limit: String(PAGE_SIZE),
    });
    const blocks = await request<Block[]>(
      "/api/firewall/blocked?" + params,
      client,
    );
    if (active(client) && id === seq.current[3])
      setData((old) => ({ ...old, blocks }));
  };
  const loadFeed = async (client: Session) => {
    const feed = await request<Detection[]>("/api/alerts?limit=8", client);
    if (active(client))
      setData((old) => ({ ...old, feed: mergeFeed(old.feed, feed) }));
  };
  const updateQuery = (patch: Partial<Query>) => {
    queryRef.current = { ...queryRef.current, ...patch };
    setQuery(queryRef.current);
    const client = sessionRef.current;
    if (client)
      void Promise.all([
        loadAlerts(client),
        loadBlocks(client),
        loadAnalytics(client),
      ]).catch((error) => fail(error, client));
  };
  const refreshAll = (manual = false): Promise<void> => {
    const client = sessionRef.current;
    if (!client) return Promise.resolve();
    if (refreshing.current?.client === client)
      return refreshing.current.promise;
    setBusy(true);
    const promise = Promise.allSettled([
      loadStats(client),
      loadAnalytics(client),
      loadAlerts(client),
      loadBlocks(client),
      loadFeed(client),
    ])
      .then((results) => {
        if (!active(client)) return;
        const failure = results.find((result) => result.status === "rejected");
        setUnavailable(Boolean(failure));
        if (failure?.status === "rejected") fail(failure.reason, client);
        else if (manual && !pendingCommand.current)
          announce("Workspace updated from the API.");
      })
      .finally(() => {
        if (active(client)) {
          setBusy(false);
          refreshing.current = null;
        }
      });
    refreshing.current = { client, promise };
    return promise;
  };

  useEffect(() => {
    if (!session) return;
    void refreshAll();
    void request<{ protected_cidrs: string[] }>(
      "/api/firewall/whitelist",
      session,
    )
      .then((result) => {
        if (active(session))
          setData((old) => ({ ...old, cidrs: result.protected_cidrs }));
      })
      .catch((error) => fail(error, session));
  }, [session]);
  useEffect(() => {
    if (!session || !expiresAt) return;
    const timer = setTimeout(
      () => void refreshAccess(),
      Math.max(1000, expiresAt - Date.now() - 30000),
    );
    return () => clearTimeout(timer);
  }, [session, expiresAt]);
  useEffect(() => {
    if (!sessionRef.current && getRefresh()) void refreshAccess();
    const tick = () => {
      if (!document.hidden) void refreshAll();
    };
    const timer = setInterval(tick, 5000);
    document.addEventListener("visibilitychange", tick);
    return () => {
      clearInterval(timer);
      document.removeEventListener("visibilitychange", tick);
    };
  }, []);

  useEffect(() => {
    if (!session) return;
    let stopped = false,
      connecting = false,
      failures = 0;
    let socket: WebSocket | null = null;
    let retry: ReturnType<typeof setTimeout> | undefined;
    let opening: ReturnType<typeof setTimeout> | undefined;
    let update: ReturnType<typeof setTimeout> | undefined;
    function disconnect() {
      clearTimeout(retry);
      clearTimeout(opening);
      const previous = socket;
      socket = null;
      if (previous) {
        previous.onclose = null;
        previous.close();
      }
      if (!stopped) setConnection("Disconnected");
    }
    function schedule() {
      if (stopped || !active(session!) || !navigator.onLine) return;
      if (++failures > 10) {
        setConnection("Disconnected");
        announce("Alert stream disconnected. Use Refresh to reconnect.", true);
        return;
      }
      setConnection("Reconnecting");
      retry = setTimeout(
        () => void connect(),
        Math.min(30000, 750 * 2 ** (failures - 1)),
      );
    }
    async function connect() {
      if (stopped || connecting || socket || !navigator.onLine) return;
      connecting = true;
      setConnection("Connecting");
      try {
        const ticket = await request<{ ticket: string }>(
          "/api/auth/ws-ticket",
          session,
          { method: "POST" },
        );
        if (stopped || !active(session!)) return;
        const url = new URL("/ws/alerts", location.href);
        url.protocol = location.protocol === "https:" ? "wss:" : "ws:";
        url.searchParams.set("ticket", ticket.ticket);
        const current = new WebSocket(url);
        socket = current;
        opening = setTimeout(() => {
          if (current.readyState === WebSocket.CONNECTING) current.close();
        }, 10000);
        current.onopen = () => {
          clearTimeout(opening);
          if (stopped || current !== socket) return current.close();
          failures = 0;
          setConnection("Connected");
          void refreshAll();
        };
        current.onmessage = (event) => {
          if (stopped || current !== socket) return;
          let value: Detection & { type?: string };
          try {
            value = JSON.parse(String(event.data)) as typeof value;
          } catch {
            return;
          }
          if (value.type !== "detection" || typeof value.event_id !== "string")
            return;
          setData((old) => ({ ...old, feed: mergeFeed(old.feed, [value]) }));
          if (!update)
            update = setTimeout(() => {
              update = undefined;
              void refreshAll();
            }, 100);
        };
        current.onclose = () => {
          clearTimeout(opening);
          if (socket === current) {
            socket = null;
            schedule();
          }
        };
        current.onerror = () => current.close();
      } catch (error) {
        if (!stopped && active(session!)) {
          if (error instanceof ApiError && error.status === 401)
            fail(error, session!);
          else schedule();
        }
      } finally {
        connecting = false;
      }
    }
    const online = () => {
      failures = 0;
      void connect();
      void refreshAll();
    };
    window.addEventListener("offline", disconnect);
    window.addEventListener("online", online);
    void connect();
    return () => {
      stopped = true;
      disconnect();
      clearTimeout(update);
      window.removeEventListener("offline", disconnect);
      window.removeEventListener("online", online);
    };
  }, [session, reconnectKey]);

  const unblock = async (block: Block) => {
    const client = sessionRef.current;
    if (!client || !block.block_id) return;
    try {
      const result = await request<{ command_id: string }>(
        `/api/firewall/unblock/${encodeURIComponent(block.ip)}?block_id=${encodeURIComponent(block.block_id)}`,
        client,
        { method: "POST" },
      );
      if (!active(client)) return;
      pendingCommand.current = result.command_id;
      seq.current[0]++;
      announce("Unblock requested. Waiting for sensor acknowledgement.");
      queryRef.current = {
        ...queryRef.current,
        blockStatus: "UNBLOCK_REQUESTED",
        blockOffset: 0,
      };
      setQuery(queryRef.current);
      await Promise.all([loadStats(client), loadBlocks(client)]);
    } catch (error) {
      fail(error, client);
    }
  };
  const provision = async (body: NewUser) => {
    const client = sessionRef.current;
    if (!client) throw new Error("Authentication required");
    try {
      const user = await request<User>("/api/auth/register", client, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(body),
      });
      if (!active(client)) throw new Error("Session ended");
      announce(`Account ${user.username} created successfully.`);
      return user;
    } catch (error) {
      if (error instanceof ApiError && error.status === 401)
        fail(error, client);
      throw error;
    }
  };
  const refresh = () => {
    if (connection !== "Connected") setReconnectKey((value) => value + 1);
    void refreshAll(true);
  };
  return {
    user: session?.user ?? null,
    data,
    query,
    notice,
    loginError,
    connection,
    busy,
    unavailable,
    login,
    logout,
    refresh,
    announce,
    updateQuery,
    unblock,
    provision,
  };
}
export type Platform = ReturnType<typeof usePlatform>;
