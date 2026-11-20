import type { BrowserWorker } from "@cloudflare/playwright";
import { runScan, type ScanResult, type Bug } from "./scan";

export interface Env {
  MYBROWSER: BrowserWorker;
  DB: D1Database;
  SCREENSHOTS: R2Bucket;
  SCAN_QUEUE: Queue;
  WORKER_API_TOKEN: string;
  ALLOWED_ORIGINS?: string;
}

interface ScanRequest {
  url: string;
  maxPages?: number;
  testMobile?: boolean;
  includeAccessibility?: boolean;
}

const CORS_METHODS = "GET, POST, OPTIONS";
const CORS_HEADERS = "Authorization, Content-Type";

function corsHeaders(request: Request, env: Env): Record<string, string> {
  const origin = request.headers.get("Origin") ?? "";
  const allowed = (env.ALLOWED_ORIGINS ?? "").split(",").map((x) => x.trim()).filter(Boolean);
  const headers: Record<string, string> = {
    "Access-Control-Allow-Methods": CORS_METHODS,
    "Access-Control-Allow-Headers": CORS_HEADERS,
    "Vary": "Origin",
  };
  if (origin && allowed.includes(origin)) headers["Access-Control-Allow-Origin"] = origin;
  return headers;
}

async function authorized(request: Request, env: Env): Promise<boolean> {
  const supplied = request.headers.get("Authorization") ?? "";
  const expected = env.WORKER_API_TOKEN ?? "";
  if (!expected || !supplied.startsWith("Bearer ")) return false;
  const enc = new TextEncoder();
  const [a, b] = await Promise.all([
    crypto.subtle.digest("SHA-256", enc.encode(supplied.slice(7))),
    crypto.subtle.digest("SHA-256", enc.encode(expected)),
  ]);
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
    INSERT INTO worker_rate_limits (ip_hash, window_start, request_count)
    VALUES (?, CAST(strftime('%s','now') AS INTEGER) / 60, 1)
    ON CONFLICT(ip_hash) DO UPDATE SET
      request_count = CASE WHEN worker_rate_limits.window_start = excluded.window_start
        THEN worker_rate_limits.request_count + 1 ELSE 1 END,
      window_start = excluded.window_start
    RETURNING request_count
  `).bind(key).first<{request_count:number}>();
  return (row?.request_count ?? 999) <= 30;
}


async function readScanRequest(request: Request): Promise<ScanRequest> {
  const declared = Number(request.headers.get("Content-Length") ?? "0");
  if (declared > 16_384) throw new Error("request body too large");
  if (!request.body) throw new Error("empty request body");
  const reader = request.body.getReader();
  const chunks: Uint8Array[] = [];
  let total = 0;
  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      total += value.byteLength;
      if (total > 16_384) {
        await reader.cancel();
        throw new Error("request body too large");
      }
      chunks.push(value);
    }
  } finally {
    reader.releaseLock();
  }
  const bytes = new Uint8Array(total);
  let offset = 0;
  for (const chunk of chunks) { bytes.set(chunk, offset); offset += chunk.byteLength; }
  return JSON.parse(new TextDecoder().decode(bytes)) as ScanRequest;
}

function json(data: unknown, status = 200): Response {
  return new Response(JSON.stringify(data), { status, headers: { "Content-Type": "application/json" } });
}

async function uploadScreenshots(env: Env, scanId: string, result: ScanResult): Promise<Record<string, string>> {
  // Uploads once per unique page screenshot, returns a map of page URL -> R2 key
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
    env.DB.prepare(
      `UPDATE scans SET status=?, pages_tested=?, passed_checks=?, error=?, updated_at=datetime('now') WHERE id=?`
    ).bind(status, result.pages.length, result.passed, error, scanId),
    ...result.pages.map((p) =>
      env.DB.prepare(`INSERT INTO pages (scan_id, url, status, screenshot_key) VALUES (?, ?, ?, ?)`)
        .bind(scanId, p.url, p.status, keyByUrl[p.url] ?? null)
    ),
    ...result.bugs.map((b: Bug) =>
      env.DB.prepare(
        `INSERT INTO bugs (id, scan_id, title, severity, priority, type, page, message, evidence, wcag,
                            selector, html_snippet, remediation, steps, expected, actual, help_url, screenshot_key)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
      ).bind(
        b.id, scanId, b.title, b.severity, b.priority, b.type, b.page, b.message, b.evidence, b.wcag,
        b.selector, b.html_snippet, b.remediation, b.steps, b.expected, b.actual, b.help_url,
        keyByUrl[b.page] ?? null
      )
    ),
  ]);
}

function resultToJson(scanId: string, result: ScanResult, keyByUrl: Record<string, string>, workerUrl: string) {
  // Shapes the response to match scanner.py's run_scan() output, with
  // screenshot fields replaced by fetchable URLs instead of local paths.
  return {
    id: scanId,
    target: result.target,
    passed: result.passed,
    pages: result.pages.map((p) => ({
      url: p.url, status: p.status,
      screenshot_url: keyByUrl[p.url] ? `${workerUrl}/screenshot/${keyByUrl[p.url]}` : null,
    })),
    bugs: result.bugs.map((b) => ({
      ...b,
      screenshotBytes: undefined,
      screenshot_url: keyByUrl[b.page] ? `${workerUrl}/screenshot/${keyByUrl[b.page]}` : null,
    })),
  };
}

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    const url = new URL(request.url);

    if (request.method === "OPTIONS") return new Response(null, { headers: corsHeaders(request, env) });
    if (!await authorized(request, env)) return json({ error: "unauthorized" }, 401);
    if (!await rateAllowed(request, env)) return json({ error: "rate limit exceeded" }, 429);
    if (request.method === "POST") {
      const length = Number(request.headers.get("Content-Length") ?? "0");
      if (length > 16_384) return json({ error: "request body too large" }, 413);
    }

    // --- Synchronous scan: good for small/medium sites, one HTTP round trip ---
    if (url.pathname === "/scan" && request.method === "POST") {
      let body: ScanRequest;
      try { body = await readScanRequest(request); }
      catch (e) { return json({ error: String(e).includes("too large") ? "request body too large" : "invalid JSON" }, String(e).includes("too large") ? 413 : 400); }
      if (!body.url || typeof body.url !== "string") return json({ error: "url is required" }, 400);
      if (body.url.length > 2048) return json({ error: "URL too long" }, 400);
      if (body.maxPages !== undefined && (!Number.isInteger(body.maxPages) || body.maxPages < 1 || body.maxPages > 50)) return json({ error: "maxPages must be an integer from 1 to 50" }, 400);
      const active = await env.DB.prepare("SELECT COUNT(*) AS n FROM scans WHERE status IN ('queued','running')").first<{n:number}>();
      if ((active?.n ?? 0) >= 5) return json({ error: "scan capacity reached" }, 429);

      const scanId = crypto.randomUUID();
      const opts = {
        maxPages: body.maxPages ?? 10,
        testMobile: body.testMobile ?? true,
        includeAccessibility: body.includeAccessibility ?? true,
      };

      await env.DB.prepare(
        `INSERT INTO scans (id, target, status, max_pages, test_mobile, include_accessibility) VALUES (?, ?, 'running', ?, ?, ?)`
      ).bind(scanId, body.url, opts.maxPages, opts.testMobile ? 1 : 0, opts.includeAccessibility ? 1 : 0).run();

      try {
        const result = await runScan(env.MYBROWSER, body.url, opts);
        const keyByUrl = await uploadScreenshots(env, scanId, result);
        await persistScan(env, scanId, result, "complete", null, keyByUrl);
        return json(resultToJson(scanId, result, keyByUrl, url.origin));
      } catch (e) {
        await env.DB.prepare(`UPDATE scans SET status='failed', error=?, updated_at=datetime('now') WHERE id=?`)
          .bind(String(e), scanId).run();
        return json({ error: String(e), id: scanId }, 500);
      }
    }

    // --- Async scan: for larger crawls, returns immediately with a job id ---
    if (url.pathname === "/scan/async" && request.method === "POST") {
      let body: ScanRequest;
      try { body = await readScanRequest(request); }
      catch (e) { return json({ error: String(e).includes("too large") ? "request body too large" : "invalid JSON" }, String(e).includes("too large") ? 413 : 400); }
      if (!body.url || typeof body.url !== "string") return json({ error: "url is required" }, 400);
      if (body.url.length > 2048) return json({ error: "URL too long" }, 400);
      if (body.maxPages !== undefined && (!Number.isInteger(body.maxPages) || body.maxPages < 1 || body.maxPages > 50)) return json({ error: "maxPages must be an integer from 1 to 50" }, 400);
      const active = await env.DB.prepare("SELECT COUNT(*) AS n FROM scans WHERE status IN ('queued','running')").first<{n:number}>();
      if ((active?.n ?? 0) >= 5) return json({ error: "scan capacity reached" }, 429);

      const scanId = crypto.randomUUID();
      const opts = {
        maxPages: body.maxPages ?? 10,
        testMobile: body.testMobile ?? true,
        includeAccessibility: body.includeAccessibility ?? true,
      };

      await env.DB.prepare(
        `INSERT INTO scans (id, target, status, max_pages, test_mobile, include_accessibility) VALUES (?, ?, 'queued', ?, ?, ?)`
      ).bind(scanId, body.url, opts.maxPages, opts.testMobile ? 1 : 0, opts.includeAccessibility ? 1 : 0).run();

      await env.SCAN_QUEUE.send({ scanId, url: body.url, opts });
      return json({ id: scanId, status: "queued" });
    }

    // --- Poll job status / fetch results once complete ---
    const jobMatch = url.pathname.match(/^\/scan\/([a-f0-9-]+)$/);
    if (jobMatch && request.method === "GET") {
      const scanId = jobMatch[1];
      const scan = await env.DB.prepare(`SELECT * FROM scans WHERE id = ?`).bind(scanId).first();
      if (!scan) return json({ error: "not found" }, 404);

      if (scan.status !== "complete") {
        return json({ id: scanId, status: scan.status, error: scan.error ?? null });
      }

      const pages = await env.DB.prepare(`SELECT * FROM pages WHERE scan_id = ?`).bind(scanId).all();
      const bugs = await env.DB.prepare(`SELECT * FROM bugs WHERE scan_id = ?`).bind(scanId).all();

      return json({
        id: scanId,
        target: scan.target,
        status: scan.status,
        passed: scan.passed_checks,
        pages: pages.results.map((p: any) => ({
          url: p.url, status: p.status,
          screenshot_url: p.screenshot_key ? `${url.origin}/screenshot/${p.screenshot_key}` : null,
        })),
        bugs: bugs.results.map((b: any) => ({
          ...b,
          screenshot_url: b.screenshot_key ? `${url.origin}/screenshot/${b.screenshot_key}` : null,
        })),
      });
    }

    // --- Serve a screenshot out of R2 ---
    const shotMatch = url.pathname.match(/^\/screenshot\/(.+)$/);
    if (shotMatch && request.method === "GET") {
      const obj = await env.SCREENSHOTS.get(decodeURIComponent(shotMatch[1]));
      if (!obj) return new Response("Not found", { status: 404 });
      return new Response(obj.body, { headers: { "Content-Type": "image/png", "Cache-Control": "private, no-store", ...corsHeaders(request, env) } });
    }

    return new Response(JSON.stringify({ error: "not found" }), { status: 404, headers: { "Content-Type": "application/json", ...corsHeaders(request, env) } });
  },

  // --- Queue consumer: does the actual crawl for async jobs ---
  async queue(batch: MessageBatch<{ scanId: string; url: string; opts: any }>, env: Env) {
    for (const msg of batch.messages) {
      const { scanId, url: target, opts } = msg.body;
      await env.DB.prepare(`UPDATE scans SET status='running', updated_at=datetime('now') WHERE id=?`).bind(scanId).run();
      try {
        const result = await runScan(env.MYBROWSER, target, opts);
        await persistScan(env, scanId, result, "complete");
      } catch (e) {
        await env.DB.prepare(`UPDATE scans SET status='queued', error=?, updated_at=datetime('now') WHERE id=?`)
          .bind(String(e), scanId).run();
        msg.retry({ delaySeconds: 30 });
        continue;
      }
      msg.ack();
    }
  },
};
