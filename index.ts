import type { BrowserWorker } from "@cloudflare/playwright";
import { runScan, type ScanResult, type Bug, type ScanFetcher } from "./scan";
import { validateDestination } from "./network_policy";

export interface Env {
  MYBROWSER: BrowserWorker;
  DB: D1Database;
  SCREENSHOTS: R2Bucket;
  SCAN_QUEUE: Queue;
  WORKER_API_TOKEN: string;
  ALLOWED_ORIGINS?: string;
  EGRESS_GATEWAY_URL: string;
  EGRESS_GATEWAY_TOKEN: string;
}
interface ScanRequest { url: string; maxPages?: number; testMobile?: boolean; includeAccessibility?: boolean; }
const CORS_METHODS = "GET, POST, OPTIONS";
const CORS_HEADERS = "Authorization, Content-Type";
function corsHeaders(request: Request, env: Env): Record<string, string> {
  const origin = request.headers.get("Origin") ?? "";
  const allowed = (env.ALLOWED_ORIGINS ?? "").split(",").map((x) => x.trim()).filter(Boolean);
  const headers: Record<string, string> = { "Access-Control-Allow-Methods": CORS_METHODS, "Access-Control-Allow-Headers": CORS_HEADERS, Vary: "Origin" };
  if (origin && allowed.includes(origin)) headers["Access-Control-Allow-Origin"] = origin;
  return headers;
}
async function authorized(request: Request, env: Env): Promise<boolean> {
  const supplied = request.headers.get("Authorization") ?? "";
  const expected = env.WORKER_API_TOKEN ?? "";
  if (!expected || !supplied.startsWith("Bearer ")) return false;
  const enc = new TextEncoder();
  const [a, b] = await Promise.all([crypto.subtle.digest("SHA-256", enc.encode(supplied.slice(7))), crypto.subtle.digest("SHA-256", enc.encode(expected))]);
  const aa = new Uint8Array(a), bb = new Uint8Array(b);
  let diff = 0;
  for (let i = 0; i < aa.length; i++) diff |= aa[i] ^ bb[i];
  return diff === 0;
}
async function rateAllowed(request: Request, env: Env): Promise<boolean> {
  const ip = request.headers.get("CF-Connecting-IP") ?? "unknown";
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(ip));
  const key = Array.from(new Uint8Array(digest)).map((b) => b.toString(16).padStart(2, "0")).join("");
  const row = await env.DB.prepare(`
    INSERT INTO worker_rate_limits (ip_hash, window_start, request_count) VALUES (?, CAST(strftime('%s','now') AS INTEGER) / 60, 1)
    ON CONFLICT(ip_hash) DO UPDATE SET request_count = CASE WHEN worker_rate_limits.window_start = excluded.window_start THEN worker_rate_limits.request_count + 1 ELSE 1 END,
    window_start = excluded.window_start RETURNING request_count
  `).bind(key).first<{request_count:number}>();
  return (row?.request_count ?? 999) <= 30;
}
async function readScanRequest(request: Request): Promise<ScanRequest> {
  const declared = Number(request.headers.get("Content-Length") ?? "0");
  if (declared > 16_384) throw new Error("request body too large");
  if (!request.body) throw new Error("empty request body");
  const reader = request.body.getReader(), chunks: Uint8Array[] = [];
  let total = 0;
  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      total += value.byteLength;
      if (total > 16_384) { await reader.cancel(); throw new Error("request body too large"); }
      chunks.push(value);
    }
  } finally { reader.releaseLock(); }
  const bytes = new Uint8Array(total); let offset = 0;
  for (const chunk of chunks) { bytes.set(chunk, offset); offset += chunk.byteLength; }
  return JSON.parse(new TextDecoder().decode(bytes)) as ScanRequest;
}
function makeGatewayFetch(env: Env): ScanFetcher {
  return async (input, _init, scopeOrigin) => {
    const target = await validateDestination(input);
    if (scopeOrigin && target.origin !== scopeOrigin) throw new Error("Cross-origin scan destination blocked.");
    if (!env.EGRESS_GATEWAY_URL || !env.EGRESS_GATEWAY_TOKEN) throw new Error("Egress gateway is not configured.");
    const gateway = new URL(env.EGRESS_GATEWAY_URL);
    if (gateway.protocol !== "https:" || gateway.username || gateway.password) throw new Error("Egress gateway must be a trusted HTTPS endpoint.");
    const response = await fetch(new URL("/fetch", gateway).toString(), {
      method: "POST", redirect: "error", signal: AbortSignal.timeout(25000),
      headers: { "Authorization": "Bearer " + env.EGRESS_GATEWAY_TOKEN, "Content-Type": "application/json" },
      body: JSON.stringify({ url: target.toString() }),
    });
    if (!response.ok) throw new Error("Egress gateway request failed.");
    const payload = await response.json() as { status: number; headers: Record<string,string>; body: string };
    if (!Number.isInteger(payload.status) || typeof payload.body !== "string" || !payload.headers) throw new Error("Invalid egress gateway response.");
    const binary = atob(payload.body);
    if (binary.length > 2 * 1024 * 1024) throw new Error("Egress response exceeds scan limit.");
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
    return new Response(bytes, { status: payload.status, headers: payload.headers });
  };
}
function json(data: unknown, status = 200, headers: Record<string,string> = {}): Response {
  return new Response(JSON.stringify(data), { status, headers: { "Content-Type": "application/json", ...headers } });
}
async function uploadScreenshots(env: Env, scanId: string, result: ScanResult): Promise<Record<string, string>> {
  const keyByUrl: Record<string, string> = {};
  for (const p of result.pages) {
    if (!p.screenshotBytes) continue;
    const key = `${scanId}/${encodeURIComponent(p.url)}.png`;
    await env.SCREENSHOTS.put(key, p.screenshotBytes, { httpMetadata: { contentType: "image/png" } });
    keyByUrl[p.url] = key;
  }
  return keyByUrl;
}
async function persistScan(env: Env, scanId: string, result: ScanResult, status = "complete", error: string | null = null, uploadedKeys?: Record<string, string>) {
  const keyByUrl = uploadedKeys ?? await uploadScreenshots(env, scanId, result);
  await env.DB.batch([
    env.DB.prepare("UPDATE scans SET status=?, pages_tested=?, passed_checks=?, total_checks=?, error=?, updated_at=datetime('now') WHERE id=?").bind(status, result.pages.length, result.passed, result.totalChecks, error, scanId),
    ...result.pages.map((p) => env.DB.prepare("INSERT INTO pages (scan_id, url, status, screenshot_key) VALUES (?, ?, ?, ?)").bind(scanId, p.url, p.status, keyByUrl[p.url] ?? null)),
    ...result.bugs.map((b: Bug) => env.DB.prepare(`INSERT INTO bugs (id, scan_id, title, severity, priority, type, page, message, evidence, wcag, selector, html_snippet, remediation, steps, expected, actual, help_url, screenshot_key) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`).bind(
      b.id, scanId, b.title, b.severity, b.priority, b.type, b.page, b.message, b.evidence, b.wcag, b.selector, b.html_snippet, b.remediation, b.steps, b.expected, b.actual, b.help_url, keyByUrl[b.page] ?? null
    )),
  ]);
}
function resultToJson(scanId: string, result: ScanResult, keyByUrl: Record<string, string>, workerUrl: string) {
  return { id: scanId, target: result.target, passed: result.passed, total_checks: result.totalChecks,
    pages: result.pages.map((p) => ({ url: p.url, status: p.status, screenshot_url: keyByUrl[p.url] ? `${workerUrl}/screenshot/${keyByUrl[p.url]}` : null })),
    bugs: result.bugs.map((b) => ({ ...b, screenshotBytes: undefined, screenshot_url: keyByUrl[b.page] ? `${workerUrl}/screenshot/${keyByUrl[b.page]}` : null })) };
}
export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    const url = new URL(request.url), cors = corsHeaders(request, env);
    if (request.method === "OPTIONS") return new Response(null, { headers: cors });
    if (!await authorized(request, env)) return json({ error: "unauthorized" }, 401, cors);
    if (!await rateAllowed(request, env)) return json({ error: "rate limit exceeded" }, 429, cors);
    if (request.method === "POST" && Number(request.headers.get("Content-Length") ?? "0") > 16_384) return json({ error: "request body too large" }, 413, cors);

    if (url.pathname === "/scan" && request.method === "POST") {
      let body: ScanRequest;
      try { body = await readScanRequest(request); } catch (e) { const large = String(e).includes("too large"); return json({ error: large ? "request body too large" : "invalid JSON" }, large ? 413 : 400, cors); }
      if (!body.url || typeof body.url !== "string") return json({ error: "url is required" }, 400, cors);
      if (body.url.length > 2048) return json({ error: "URL too long" }, 400, cors);
      if (body.maxPages !== undefined && (!Number.isInteger(body.maxPages) || body.maxPages < 1 || body.maxPages > 50)) return json({ error: "maxPages must be an integer from 1 to 50" }, 400, cors);
      const active = await env.DB.prepare("SELECT COUNT(*) AS n FROM scans WHERE status IN ('queued','running')").first<{n:number}>();
      if ((active?.n ?? 0) >= 5) return json({ error: "scan capacity reached" }, 429, cors);
      const scanId = crypto.randomUUID(), opts = { maxPages: body.maxPages ?? 10, testMobile: body.testMobile ?? true, includeAccessibility: body.includeAccessibility ?? true };
      await env.DB.prepare("INSERT INTO scans (id, target, status, max_pages, test_mobile, include_accessibility) VALUES (?, ?, 'running', ?, ?, ?)").bind(scanId, body.url, opts.maxPages, opts.testMobile ? 1 : 0, opts.includeAccessibility ? 1 : 0).run();
      try {
        const result = await runScan(env.MYBROWSER, body.url, opts, makeGatewayFetch(env)), keys = await uploadScreenshots(env, scanId, result);
        await persistScan(env, scanId, result, "complete", null, keys);
        return json(resultToJson(scanId, result, keys, url.origin), 200, cors);
      } catch (e) {
        await env.DB.prepare("UPDATE scans SET status='failed', error=?, updated_at=datetime('now') WHERE id=?").bind(String(e), scanId).run();
        return json({ error: String(e), id: scanId }, 500, cors);
      }
    }
    if (url.pathname === "/scan/async" && request.method === "POST") {
      let body: ScanRequest;
      try { body = await readScanRequest(request); } catch (e) { const large = String(e).includes("too large"); return json({ error: large ? "request body too large" : "invalid JSON" }, large ? 413 : 400, cors); }
      if (!body.url || typeof body.url !== "string") return json({ error: "url is required" }, 400, cors);
      if (body.url.length > 2048) return json({ error: "URL too long" }, 400, cors);
      if (body.maxPages !== undefined && (!Number.isInteger(body.maxPages) || body.maxPages < 1 || body.maxPages > 50)) return json({ error: "maxPages must be an integer from 1 to 50" }, 400, cors);
      const active = await env.DB.prepare("SELECT COUNT(*) AS n FROM scans WHERE status IN ('queued','running')").first<{n:number}>();
      if ((active?.n ?? 0) >= 5) return json({ error: "scan capacity reached" }, 429, cors);
      const scanId = crypto.randomUUID(), opts = { maxPages: body.maxPages ?? 10, testMobile: body.testMobile ?? true, includeAccessibility: body.includeAccessibility ?? true };
      await env.DB.prepare("INSERT INTO scans (id, target, status, max_pages, test_mobile, include_accessibility) VALUES (?, ?, 'queued', ?, ?, ?)").bind(scanId, body.url, opts.maxPages, opts.testMobile ? 1 : 0, opts.includeAccessibility ? 1 : 0).run();
      try { await env.SCAN_QUEUE.send({ scanId, url: body.url, opts }); }
      catch (e) {
        await env.DB.prepare("UPDATE scans SET status='failed', error=?, updated_at=datetime('now') WHERE id=?").bind(`Queue submission failed: ${String(e)}`, scanId).run();
        return json({ error: "scan queue unavailable", id: scanId }, 503, cors);
      }
      return json({ id: scanId, status: "queued" }, 202, cors);
    }
    const jobMatch = url.pathname.match(/^\/scan\/([a-f0-9-]+)$/);
    if (jobMatch && request.method === "GET") {
      const scanId = jobMatch[1], scan = await env.DB.prepare("SELECT * FROM scans WHERE id = ?").bind(scanId).first();
      if (!scan) return json({ error: "not found" }, 404, cors);
      if (scan.status !== "complete") return json({ id: scanId, status: scan.status, error: scan.error ?? null }, 200, cors);
      const pages = await env.DB.prepare("SELECT * FROM pages WHERE scan_id = ?").bind(scanId).all();
      const bugs = await env.DB.prepare("SELECT * FROM bugs WHERE scan_id = ?").bind(scanId).all();
      return json({ id: scanId, target: scan.target, status: scan.status, passed: scan.passed_checks, total_checks: scan.total_checks,
        pages: pages.results.map((p: any) => ({ url: p.url, status: p.status, screenshot_url: p.screenshot_key ? `${url.origin}/screenshot/${p.screenshot_key}` : null })),
        bugs: bugs.results.map((b: any) => ({ ...b, screenshot_url: b.screenshot_key ? `${url.origin}/screenshot/${b.screenshot_key}` : null })) }, 200, cors);
    }
    const shotMatch = url.pathname.match(/^\/screenshot\/(.+)$/);
    if (shotMatch && request.method === "GET") {
      let key: string;
      try { key = decodeURIComponent(shotMatch[1]); } catch { return new Response("Bad request", { status: 400, headers: cors }); }
      if (!/^[a-f0-9-]{36}\/.+\.png$/.test(key)) return new Response("Not found", { status: 404, headers: cors });
      const obj = await env.SCREENSHOTS.get(key);
      if (!obj) return new Response("Not found", { status: 404, headers: cors });
      return new Response(obj.body, { headers: { "Content-Type": "image/png", "X-Content-Type-Options": "nosniff", "Cache-Control": "private, no-store", ...cors } });
    }
    return json({ error: "not found" }, 404, cors);
  },
  async queue(batch: MessageBatch<{ scanId: string; url: string; opts: any }>, env: Env) {
    for (const msg of batch.messages) {
      const { scanId, url: target, opts } = msg.body;
      await env.DB.prepare("UPDATE scans SET status='running', error=NULL, updated_at=datetime('now') WHERE id=?").bind(scanId).run();
      try {
        const result = await runScan(env.MYBROWSER, target, opts, makeGatewayFetch(env));
        await persistScan(env, scanId, result, "complete");
        msg.ack();
      } catch (e) {
        const error = String(e).slice(0, 2000);
        // max_retries=3 means one initial delivery plus three retries (four attempts).
        if (msg.attempts >= 4) {
          await env.DB.prepare("UPDATE scans SET status='failed', error=?, updated_at=datetime('now') WHERE id=?").bind(`Retries exhausted after ${msg.attempts} attempts: ${error}`, scanId).run();
          msg.ack();
        } else {
          await env.DB.prepare("UPDATE scans SET status='queued', error=?, updated_at=datetime('now') WHERE id=?").bind(error, scanId).run();
          msg.retry({ delaySeconds: Math.min(30 * msg.attempts, 300) });
        }
      }
    }
  },
};
