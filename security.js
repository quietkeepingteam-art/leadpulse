// netlify/functions/lib/security.js
// Shared helpers for the serverless functions. Lives in a subfolder (not the
// functions root) so Netlify doesn't treat this file as an endpoint itself.

const ALLOWED_ORIGINS = ['https://leadpulseconsultancy.com'];
const LOCALHOST_RE = /^https?:\/\/(localhost|127\.0\.0\.1)(:\d+)?$/;

// Exact-match check. The previous version used origin.startsWith(allowed),
// which "https://leadpulseconsultancy.com.evil.com".startsWith("https://leadpulseconsultancy.com")
// happily passes — that's a spoofable bypass, not a real allowlist. This
// compares the full origin string (or the origin parsed out of Referer) and
// nothing else.
function isAllowedOriginString(originStr) {
  if (!originStr) return false;
  return ALLOWED_ORIGINS.includes(originStr) || LOCALHOST_RE.test(originStr);
}

function isAllowedOrigin(headers) {
  const originHeader = headers.origin;
  if (originHeader) {
    return isAllowedOriginString(originHeader);
  }
  const refererHeader = headers.referer;
  if (refererHeader) {
    try {
      const u = new URL(refererHeader);
      return isAllowedOriginString(`${u.protocol}//${u.host}`);
    } catch (e) {
      return false;
    }
  }
  return false;
}

// Best-effort per-IP rate limiting, in memory. This resets whenever the
// function container recycles and isn't shared across concurrent/scaled
// instances, so it's a speed bump against casual abuse and brute-forcing —
// not a hard guarantee. For real guarantees, back this with Supabase or a
// service like Upstash Redis so counts persist and are shared across
// instances.
const buckets = new Map();

function rateLimit(key, { limit, windowMs }) {
  const now = Date.now();
  const entry = buckets.get(key);
  if (!entry || now - entry.start > windowMs) {
    buckets.set(key, { start: now, count: 1 });
    return { allowed: true };
  }
  entry.count += 1;
  if (entry.count > limit) {
    return { allowed: false, retryAfterMs: windowMs - (now - entry.start) };
  }
  return { allowed: true };
}

function clientIp(event) {
  const xff = event.headers['x-nf-client-connection-ip'] || event.headers['x-forwarded-for'] || '';
  return xff.split(',')[0].trim() || 'unknown';
}

module.exports = { isAllowedOrigin, rateLimit, clientIp };
