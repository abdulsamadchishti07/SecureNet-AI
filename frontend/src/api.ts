import type { User } from "./types";

export class ApiError extends Error {
  constructor(
    message: string,
    public readonly status: number,
  ) {
    super(message);
  }
}
export interface Session {
  token: string;
  user: User;
  expiresAt: number;
  controller: AbortController;
}

const fmt = (i: { loc?: string[]; msg?: string }) =>
  `${(i.loc || []).slice(1).join(".")}: ${i.msg || "Invalid value"}`;
function message(body: unknown, fallback: string): string {
  const d = (body as { detail?: unknown } | null)?.detail;
  if (typeof d === "string") return d;
  return Array.isArray(d) ? d.map(fmt).join("; ") : fallback;
}

export async function request<T>(
  path: string,
  session: Session | null,
  options: RequestInit = {},
): Promise<T> {
  const controller = new AbortController();
  const cancel = () => controller.abort();
  const signal = session?.controller.signal;
  if (signal?.aborted) throw new ApiError("Session ended", 0);
  signal?.addEventListener("abort", cancel, { once: true });
  const timeout = setTimeout(cancel, 15000);
  try {
    const headers = new Headers(options.headers);
    if (session) headers.set("Authorization", `Bearer ${session.token}`);
    const response = await fetch(path, {
      ...options,
      headers,
      signal: controller.signal,
      credentials: "omit",
      cache: "no-store",
      redirect: "error",
    });
    const body: unknown = await response.json().catch(() => null);
    if (!response.ok)
      throw new ApiError(
        message(body, `Request failed (${response.status}). Please retry.`),
        response.status,
      );
    if (signal?.aborted) throw new ApiError("Session ended", 0);
    if (body === null)
      throw new ApiError("The API returned an invalid response.", 0);
    return body as T;
  } catch (error) {
    if (error instanceof ApiError) throw error;
    if (error instanceof DOMException && error.name === "AbortError")
      throw new ApiError("Request cancelled or timed out. Please retry.", 0);
    throw new ApiError(
      "The API is unavailable. Check your connection and retry.",
      0,
    );
  } finally {
    clearTimeout(timeout);
    signal?.removeEventListener("abort", cancel);
  }
}
