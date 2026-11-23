import test from "node:test";
import assert from "node:assert/strict";
import { runScan } from "../scan";

test("counts passed and total checks for a clean page", async () => {
  const original = globalThis.fetch;
  globalThis.fetch = (async () => new Response("<html><head><title>Home</title></head><body><img alt=\"Logo\"></body></html>", {
    status: 200, headers: { "Content-Type": "text/html" },
  })) as typeof fetch;
  try {
    const result = await runScan(null, "https://8.8.8.8/", { maxPages: 1, includeAccessibility: true });
    assert.equal(result.totalChecks, 3);
    assert.equal(result.passed, 3);
    assert.equal(result.bugs.length, 0);
  } finally { globalThis.fetch = original; }
});

test("counts accessibility failures as failed checks", async () => {
  const original = globalThis.fetch;
  globalThis.fetch = (async () => new Response("<html><body><img src=\"x.png\"></body></html>", {
    status: 200, headers: { "Content-Type": "text/html" },
  })) as typeof fetch;
  try {
    const result = await runScan(null, "https://8.8.8.8/", { maxPages: 1, includeAccessibility: true });
    assert.equal(result.totalChecks, 3);
    assert.equal(result.passed, 1);
    assert.equal(result.bugs.length, 2);
  } finally { globalThis.fetch = original; }
});
