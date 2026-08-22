import type { BrowserWorker } from "@cloudflare/playwright";
import { runScan, type ScanResult, type Bug } from "./scan";

export interface Env {
  MYBROWSER: BrowserWorker;
  DB: D1Database;
  SCREENSHOTS: R2Bucket;
  SCAN_QUEUE: Queue;
}

interface ScanRequest {
  url: string;
  maxPages?: number;
  testMobile?: boolean;
  includeAccessibility?: boolean;
}

const CORS = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
  "Access-Control-Allow-Headers": "Content-Type",
};

function json(data: unknown, status = 200): Response {
  return new Response(JSON.stringify(data), {
    status,
    headers: { "Content-Type": "application/json", ...CORS },
  });
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

async function persistScan(env: Env, scanId: string, result: ScanResult, status = "complete", error: string | null = null) {
  const keyByUrl = await uploadScreenshots(env, scanId, result);

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

    if (request.method === "OPTIONS") return new Response(null, { headers: CORS });

    // --- Synchronous scan: good for small/medium sites, one HTTP round trip ---
    if (url.pathname === "/scan" && request.method === "POST") {
      const body = (await request.json()) as ScanRequest;
      if (!body.url) return json({ error: "url is required" }, 400);

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
        await persistScan(env, scanId, result);
        return json(resultToJson(scanId, result, keyByUrl, url.origin));
      } catch (e) {
        await env.DB.prepare(`UPDATE scans SET status='failed', error=?, updated_at=datetime('now') WHERE id=?`)
          .bind(String(e), scanId).run();
        return json({ error: String(e), id: scanId }, 500);
      }
    }

    // --- Async scan: for larger crawls, returns immediately with a job id ---
    if (url.pathname === "/scan/async" && request.method === "POST") {
      const body = (await request.json()) as ScanRequest;
      if (!body.url) return json({ error: "url is required" }, 400);

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
      return new Response(obj.body, { headers: { "Content-Type": "image/png", ...CORS } });
    }

    return json({ error: "not found" }, 404);
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
        await env.DB.prepare(`UPDATE scans SET status='failed', error=?, updated_at=datetime('now') WHERE id=?`)
          .bind(String(e), scanId).run();
      }
      msg.ack();
    }
  },
};
