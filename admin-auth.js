// netlify/functions/admin-auth.js
// Verifies the admin password server-side so it never ships in client HTML/JS.
// Set ADMIN_KEY in Netlify environment variables (same place as GEMINI_KEY).

const { isAllowedOrigin, rateLimit, clientIp } = require('./lib/security');

exports.handler = async (event) => {
  if (event.httpMethod !== 'POST') {
    return { statusCode: 405, body: 'Method not allowed' };
  }

  if (!isAllowedOrigin(event.headers)) {
    return { statusCode: 403, body: 'Forbidden' };
  }

  // Strict rate limit on password attempts: 5 / 10 min per IP. Best-effort
  // (see lib/security.js) but meaningfully slows down guessing.
  const ip = clientIp(event);
  const rl = rateLimit(`admin-auth:${ip}`, { limit: 5, windowMs: 10 * 60 * 1000 });
  if (!rl.allowed) {
    return {
      statusCode: 429,
      headers: { 'Retry-After': String(Math.ceil(rl.retryAfterMs / 1000)) },
      body: JSON.stringify({ ok: false, error: 'Too many attempts, try again later.' })
    };
  }

  const ADMIN_KEY = process.env.ADMIN_KEY;
  if (!ADMIN_KEY) {
    return { statusCode: 500, body: JSON.stringify({ error: 'ADMIN_KEY not configured in environment' }) };
  }

  try {
    const body = JSON.parse(event.body || '{}');
    const submitted = body.password || '';

    if (submitted !== ADMIN_KEY) {
      // Same response shape/timing-insensitive-ish message either way; avoid
      // leaking whether the key was even configured.
      return {
        statusCode: 401,
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ ok: false })
      };
    }

    return {
      statusCode: 200,
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ ok: true })
    };
  } catch (err) {
    return {
      statusCode: 500,
      body: JSON.stringify({ error: err.message })
    };
  }
};
