import test from "node:test";
import assert from "node:assert/strict";
import worker from "../index";

function mockEnv() {
  const updates: Array<{sql:string; values:unknown[]}> = [];
  const DB = {
    prepare(sql: string) {
      return {
        bind(...values: unknown[]) {
          return {
            async run() { updates.push({ sql, values }); return { success: true }; },
          };
        },
      };
    },
  };
  return { env: { DB } as any, updates };
}
test("marks async scan failed and acknowledges after retry exhaustion", async () => {
  const original = globalThis.fetch;
  globalThis.fetch = (async () => { throw new Error("simulated outbound failure"); }) as typeof fetch;
  const { env, updates } = mockEnv();
  let acked = false, retryDelay: number | undefined;
  const msg = {
    body: { scanId: "123e4567-e89b-12d3-a456-426614174000", url: "https://8.8.8.8/", opts: { maxPages: 1 } },
    attempts: 4,
    ack() { acked = true; },
    retry(opts: { delaySeconds: number }) { retryDelay = opts.delaySeconds; },
  };
  try {
    await worker.queue!({ messages: [msg] } as any, env);
    assert.equal(acked, true);
    assert.equal(retryDelay, undefined);
    assert.match(updates[1].sql, /status='failed'/);
    assert.match(String(updates[1].values[0]), /Retries exhausted/);
  } finally { globalThis.fetch = original; }
});
test("requeues a transient async scan failure before retry exhaustion", async () => {
  const original = globalThis.fetch;
  globalThis.fetch = (async () => { throw new Error("temporary outbound failure"); }) as typeof fetch;
  const { env, updates } = mockEnv();
  let acked = false, retryDelay: number | undefined;
  const msg = {
    body: { scanId: "123e4567-e89b-12d3-a456-426614174000", url: "https://8.8.8.8/", opts: { maxPages: 1 } },
    attempts: 1,
    ack() { acked = true; },
    retry(opts: { delaySeconds: number }) { retryDelay = opts.delaySeconds; },
  };
  try {
    await worker.queue!({ messages: [msg] } as any, env);
    assert.equal(acked, false);
    assert.equal(retryDelay, 30);
    assert.match(updates[1].sql, /status='queued'/);
  } finally { globalThis.fetch = original; }
});
