import test from "node:test";
import assert from "node:assert/strict";
import { validateDestination, safeFetch, UnsafeDestination } from "../network_policy";

test("rejects non-HTTP schemes and embedded credentials", async () => {
  await assert.rejects(() => validateDestination("file:///etc/passwd"), UnsafeDestination);
  await assert.rejects(() => validateDestination("https://user:pass@example.com"), UnsafeDestination);
});

test("rejects private, loopback, link-local and metadata IP literals", async () => {
  for (const host of ["127.0.0.1", "10.0.0.1", "192.168.1.1", "169.254.169.254", "[::1]", "[fc00::1]", "[fe80::1]"]) {
    await assert.rejects(() => validateDestination(`http://${host}`), UnsafeDestination, host);
  }
});

test("rejects non-standard ports and local hostnames", async () => {
  await assert.rejects(() => validateDestination("https://example.com:8443"), UnsafeDestination);
  await assert.rejects(() => validateDestination("http://localhost"), UnsafeDestination);
  await assert.rejects(() => validateDestination("http://service.internal"), UnsafeDestination);
});

test("permits public IP literal targets", async () => {
  assert.equal((await validateDestination("https://8.8.8.8")).hostname, "8.8.8.8");
});

test("safeFetch blocks a redirect to a private destination", async () => {
  const original = globalThis.fetch;
  globalThis.fetch = (async () => new Response(null, { status: 302, headers: { Location: "http://127.0.0.1/" } })) as typeof fetch;
  try {
    await assert.rejects(() => safeFetch("https://8.8.8.8"), UnsafeDestination);
  } finally {
    globalThis.fetch = original;
  }
});

test("safeFetch enforces scan origin on redirects", async () => {
  const original = globalThis.fetch;
  globalThis.fetch = (async () => new Response(null, { status: 302, headers: { Location: "https://9.9.9.9/" } })) as typeof fetch;
  try {
    await assert.rejects(() => safeFetch("https://8.8.8.8", {}, "https://8.8.8.8"), UnsafeDestination);
  } finally {
    globalThis.fetch = original;
  }
});
