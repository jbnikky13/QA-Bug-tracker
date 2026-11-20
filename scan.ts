import { safeFetch, validateDestination } from "./network_policy";
export interface Bug {
  id: string;
  title: string;
  severity: string;
  priority: string;
  type: string;
  page: string;
  message: string;
  evidence: string;
  wcag: string;
  selector: string;
  html_snippet: string;
  remediation: string;
  steps: string;
  expected: string;
  actual: string;
  help_url: string;
  screenshotBytes?: Uint8Array;
}

export interface ScanPage {
  url: string;
  status: number;
  screenshotBytes?: Uint8Array;
}

export interface ScanResult {
  target: string;
  pages: ScanPage[];
  bugs: Bug[];
  passed: number;
}

function bug(id: number, page: string, type: string, message: string, severity = "Medium"): Bug {
  return {
    id: `BUG-${String(id).padStart(3, "0")}`,
    title: `${type} on ${page}`,
    severity,
    priority: severity === "High" || severity === "Critical" ? "P1" : "P2",
    type,
    page,
    message,
    evidence: message,
    wcag: type === "Accessibility" ? "WCAG 2.x" : "N/A",
    selector: "N/A",
    html_snippet: "",
    remediation: "Review the affected element and correct the underlying issue.",
    steps: `1. Open ${page}\n2. Reproduce the reported condition.`,
    expected: "The page should load and behave correctly.",
    actual: message,
    help_url: "https://www.w3.org/WAI/standards-guidelines/wcag/",
  };
}

async function readHtmlLimited(response: Response, maxBytes = 2 * 1024 * 1024): Promise<string> {
  const type = response.headers.get("Content-Type") ?? "";
  if (type && !/^(text\/html|application\/xhtml\+xml)(;|$)/i.test(type)) {
    throw new Error("Target response is not HTML; content type rejected.");
  }
  const declared = Number(response.headers.get("Content-Length") ?? "0");
  if (declared > maxBytes) throw new Error("HTML response exceeds the 2 MiB scan limit.");
  if (!response.body) return "";
  const reader = response.body.getReader();
  const chunks: Uint8Array[] = [];
  let total = 0;
  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      total += value.byteLength;
      if (total > maxBytes) {
        await reader.cancel();
        throw new Error("HTML response exceeds the 2 MiB scan limit.");
      }
      chunks.push(value);
    }
  } finally {
    reader.releaseLock();
  }
  const merged = new Uint8Array(total);
  let offset = 0;
  for (const chunk of chunks) { merged.set(chunk, offset); offset += chunk.byteLength; }
  return new TextDecoder("utf-8", { fatal: false }).decode(merged);
}

function extractLinks(html: string, base: string): string[] {
  const links: string[] = [];
  const re = /<a\b[^>]*href=["']([^"']+)["']/gi;
  let match: RegExpExecArray | null;
  while ((match = re.exec(html)) !== null) {
    try {
      const u = new URL(match[1], base);
      if ((u.protocol === "http:" || u.protocol === "https:") && u.host === new URL(base).host) {
        links.push(u.toString());
      }
    } catch (_) {}
  }
  return [...new Set(links)];
}

export async function runScan(_browser: any, target: string, opts: { maxPages?: number; testMobile?: boolean; includeAccessibility?: boolean }): Promise<ScanResult> {
  const validatedTarget = await validateDestination(target);
  const requestedPages = opts.maxPages ?? 10;\n  if (!Number.isInteger(requestedPages) || requestedPages < 1 || requestedPages > 50) throw new Error("maxPages must be an integer from 1 to 50.");\n  const maxPages = requestedPages;
  const queue = [validatedTarget.toString()];
  const scanOrigin = validatedTarget.origin;
  const visited = new Set<string>();
  const pages: ScanPage[] = [];
  const bugs: Bug[] = [];

  while (queue.length && visited.size < maxPages) {
    const url = queue.shift()!;
    if (visited.has(url)) continue;
    visited.add(url);
    try {
      const response = await safeFetch(url, { headers: { "User-Agent": "QA-Bug-Tracker-Worker/1.0" } }, scanOrigin);
      const html = await readHtmlLimited(response);
      pages.push({ url, status: response.status });
      if (response.status >= 400) bugs.push(bug(bugs.length + 1, url, "HTTP error", `Page returned HTTP ${response.status}`, "High"));
      if (!/<title\b[^>]*>[^<]+<\/title>/i.test(html)) bugs.push(bug(bugs.length + 1, url, "Accessibility", "Page has no descriptive document title."));
      if (/<img\b(?![^>]*\balt=)[^>]*>/i.test(html)) bugs.push(bug(bugs.length + 1, url, "Accessibility", "One or more images are missing alt text."));
      for (const link of extractLinks(html, url)) {
        if (!visited.has(link) && !queue.includes(link) && queue.length + visited.size < maxPages) queue.push(link);
      }
    } catch (e) {
      pages.push({ url, status: 0 });
      bugs.push(bug(bugs.length + 1, url, "Page load", `Failed to load page: ${String(e)}`, "High"));
    }
  }

  return { target, pages, bugs, passed: Math.max(0, pages.length - bugs.length) };
}
