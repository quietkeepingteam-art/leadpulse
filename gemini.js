// netlify/functions/gemini.js
// Proxies requests to Gemini API so the API key stays server-side

const { isAllowedOrigin, rateLimit, clientIp } = require('./lib/security');

exports.handler = async (event) => {
  // Only allow POST
  if (event.httpMethod !== 'POST') {
    return { statusCode: 405, body: 'Method not allowed' };
  }

  if (!isAllowedOrigin(event.headers)) {
    return { statusCode: 403, body: 'Forbidden' };
  }

  // Best-effort per-IP rate limit: 20 requests / 5 min. See lib/security.js
  // for the caveats (in-memory, per container instance).
  const ip = clientIp(event);
  const rl = rateLimit(`gemini:${ip}`, { limit: 20, windowMs: 5 * 60 * 1000 });
  if (!rl.allowed) {
    return {
      statusCode: 429,
      headers: { 'Retry-After': String(Math.ceil(rl.retryAfterMs / 1000)) },
      body: JSON.stringify({ error: 'Too many requests, slow down.' })
    };
  }

  const GEMINI_KEY = process.env.GEMINI_KEY;
  if (!GEMINI_KEY) {
    return { statusCode: 500, body: JSON.stringify({ error: 'GEMINI_KEY not configured in environment' }) };
  }

  try {
    const body = JSON.parse(event.body);
    const model = body.model || 'gemini-2.5-flash';
    
    const response = await fetch(
      `https://generativelanguage.googleapis.com/v1beta/models/${model}:generateContent?key=${GEMINI_KEY}`,
      {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          contents: body.contents,
          generationConfig: body.generationConfig || { temperature: 0.1 }
        })
      }
    );

    const data = await response.json();

    return {
      statusCode: 200,
      headers: {
        'Content-Type': 'application/json',
        'Access-Control-Allow-Origin': event.headers.origin || 'https://leadpulseconsultancy.com',
      },
      body: JSON.stringify(data)
    };
  } catch (err) {
    return {
      statusCode: 500,
      body: JSON.stringify({ error: err.message })
    };
  }
};
