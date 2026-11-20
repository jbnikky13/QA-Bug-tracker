/** Outbound network policy for Worker-side scans.
 * DNS checks are defense-in-depth, not DNS pinning: a production deployment
 * must also enforce egress firewall rules against private/metadata ranges.
 */
export class UnsafeDestination extends Error {}

const ALLOWED_PORTS = new Set(["", "80", "443"]);
const DOH = "https://cloudflare-dns.com/dns-query";

function isPublicIPv4(address: string): boolean {
  const octets = address.split(".").map(Number);
  if (octets.length !== 4 || octets.some((n) => !Number.isInteger(n) || n < 0 || n > 255)) return false;
  const [a, b, c] = octets;
  if (a === 0 || a === 10 || a === 127 || a >= 224) return false;
  if (a === 169 && b === 254) return false;
  if (a === 172 && b >= 16 && b <= 31) return false;
  if (a === 192 && b === 168) return false;
  if (a === 100 && b >= 64 && b <= 127) return false;
  if (a === 192 && b === 0 && c === 0) return false;
  if (a === 192 && b === 0 && c === 2) return false;
  if (a === 198 && b === 18 && (c === 0 || c === 1)) return false;
  if (a === 198 && b === 51 && c === 100) return false;
  if (a === 203 && b === 0 && c === 113) return false;
  if (a === 192 && b === 88 && c === 99) return false;
  return true;
}

function expandIPv6(address: string): string[] {
  let value = address.toLowerCase().split("%")[0];
  if (value.includes(".")) {
    const last = value.substring(value.lastIndexOf(":") + 1);
    const v4 = last.split(".").map(Number);
    if (v4.length !== 4) return [];
    value = value.substring(0, value.lastIndexOf(":")) + ":" + ((v4[0] << 8) | v4[1]).toString(16) + ":" + ((v4[2] << 8) | v4[3]).toString(16);
  }
  const halves = value.split("::");
  if (halves.length > 2) return [];
  const left = halves[0] ? halves[0].split(":") : [];
  const right = halves.length === 2 && halves[1] ? halves[1].split(":") : [];
  const missing = 8 - left.length - right.length;
  if (missing < 0 || (halves.length === 1 && missing !== 0)) return [];
  return [...left, ...Array(missing).fill("0"), ...right].map((part) => part.padStart(4, "0"));
}

function isPublicIPv6(address: string): boolean {
  const groups = expandIPv6(address);
  if (groups.length !== 8) return false;
  const first = parseInt(groups[0], 16);
  // Block unspecified, loopback, IPv4-mapped, ULA, link-local, multicast,
  // documentation, and non-global ranges; permit only global unicast 2000::/3.
  if ((first & 0xe000) !== 0x2000) return false;
  if (groups[0] === "2001" && groups[1] === "0") return false; // Teredo
  if (groups[0] === "2001" && groups[1] === "0db8") return false; // documentation
  return true;
}

function isPublicIP(host: string): boolean {
  if (host.includes(":")) return isPublicIPv6(host.replace(/^\[|\]$/g, ""));
  if (/^\d+(\.\d+){3}$/.test(host)) return isPublicIPv4(host);
  return false;
}

export async function validateDestination(input: string): Promise<URL> {
  let url: URL;
  try { url = new URL(input); } catch { throw new UnsafeDestination("Malformed URL."); }
  if (!["http:", "https:"].includes(url.protocol)) throw new UnsafeDestination("Only HTTP/HTTPS is permitted.");
  if (url.username || url.password) throw new UnsafeDestination("Embedded URL credentials are blocked.");
  if (!ALLOWED_PORTS.has(url.port)) throw new UnsafeDestination("Non-standard ports are blocked.");
  const host = url.hostname.toLowerCase().replace(/^\[|\]$/g, "").replace(/\.$/, "");
  if (!host || host === "localhost" || host.endsWith(".localhost") || host.endsWith(".local") || host.endsWith(".internal")) {
    throw new UnsafeDestination("Local or internal hostnames are blocked.");
  }
  if (isPublicIP(host)) return url;
  if (host.includes(":") || /^\d+(\.\d+){3}$/.test(host)) throw new UnsafeDestination("Non-public IP destination blocked.");
  const resolveType = async (type: "A" | "AAAA") => {
    const query = new URL(DOH);
    query.searchParams.set("name", host);
    query.searchParams.set("type", type);
    const response = await fetch(query.toString(), { headers: { accept: "application/dns-json" }, redirect: "error" });
    if (!response.ok) throw new UnsafeDestination("DNS safety lookup failed.");
    const body = await response.json() as { Answer?: Array<{ type: number; data: string }> };
    return (body.Answer ?? []).filter((a) => (type === "A" ? a.type === 1 : a.type === 28)).map((a) => a.data);
  };
  const [v4, v6] = await Promise.all([resolveType("A"), resolveType("AAAA")]);
  if (!v4.length && !v6.length) throw new UnsafeDestination("Hostname has no DNS records.");
  if (v4.some((ip) => !isPublicIPv4(ip)) || v6.some((ip) => !isPublicIPv6(ip))) {
    throw new UnsafeDestination("Hostname resolves to a non-public address.");
  }
  return url;
}

export async function safeFetch(input: string, init: RequestInit = {}, scopeOrigin?: string): Promise<Response> {
  let current = await validateDestination(input);
  const origin = scopeOrigin ?? current.origin;
  for (let hop = 0; hop <= 5; hop++) {
    if (current.origin !== origin) throw new UnsafeDestination("Cross-origin redirect is outside the scan scope.");
    const response = await fetch(current.toString(), { ...init, redirect: "manual" });
    if (![301, 302, 303, 307, 308].includes(response.status)) return response;
    const location = response.headers.get("Location");
    if (!location) throw new UnsafeDestination("Redirect missing Location header.");
    if (hop === 5) throw new UnsafeDestination("Redirect limit exceeded.");
    current = await validateDestination(new URL(location, current).toString());
  }
  throw new UnsafeDestination("Redirect limit exceeded.");
}
