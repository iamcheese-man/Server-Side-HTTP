// This version is heavily restricted.
import express from 'express';
import os from 'os';
import dns from 'dns/promises';
import cors from 'cors';
import net from 'net';
import { parse as parseUrl } from 'url';

const app = express();
const PORT = Number(process.env.PORT) || 54839;

let fetchFunc;

// Use global fetch if available (Node 18+), else import once
(async () => {
  if (typeof fetch !== 'function') {
    fetchFunc = (await import('node-fetch')).default;
  } else {
    fetchFunc = fetch;
  }
})();

// 🔒 Simple in-memory rate limiter
const rateLimitMap = new Map();
const RATE_LIMIT_MAX = 100;
const RATE_LIMIT_WINDOW_MS = 15 * 60 * 1000; // 15 minutes

function rateLimiter(req, res, next) {
  const ip = req.ip || req.connection.remoteAddress;
  const now = Date.now();
  let entry = rateLimitMap.get(ip);

  if (!entry) {
    rateLimitMap.set(ip, { count: 1, startTime: now });
    return next();
  }

  if (now - entry.startTime > RATE_LIMIT_WINDOW_MS) {
    entry.count = 1;
    entry.startTime = now;
    return next();
  }

  if (entry.count >= RATE_LIMIT_MAX) {
    return res.status(429).json({ error: 'Too many requests. Please wait.' });
  }

  entry.count++;
  next();
}

// List of forbidden ports
const FORBIDDEN_PORTS = new Set([
  1, 7, 9, 11, 13, 15, 17, 19, 20, 21, 22, 23, 25, 37,
  42, 43, 53, 77, 79, 87, 95, 101, 102, 103, 104, 109,
  110, 111, 113, 115, 117, 119, 123, 135, 137, 139, 143,
  179, 389, 427, 465, 512, 513, 514, 515, 526, 530, 531,
  532, 540, 556, 563, 587, 601, 636, 993, 995, 2049, 3659,
  4045, 6000, 6665, 6666, 6667, 6668, 6669
]);

const normalizeHostname = (hostname) => (hostname || '').toLowerCase();

function getLocalIps() {
  const interfaces = os.networkInterfaces();
  const localIps = [];
  for (const name in interfaces) {
    for (const iface of interfaces[name]) {
      if (iface && !iface.internal && iface.address) {
        localIps.push(iface.address);
      }
    }
  }
  return localIps;
}

async function isRequestToSelf(parsedUrl, serverPort) {
  const hostname = normalizeHostname(parsedUrl.hostname);

  if (
    hostname === 'localhost' ||
    hostname === '127.0.0.1' ||
    hostname === '::1'
  ) {
    const portNum = parsedUrl.port
      ? Number(parsedUrl.port)
      : (parsedUrl.protocol === 'https:' ? 443 : 80);
    return portNum === serverPort;
  }

  const localIps = getLocalIps();
  localIps.push('127.0.0.1', '::1');

  try {
    let resolvedIps = [];
    try {
      const v4 = await dns.resolve4(hostname);
      resolvedIps.push(...v4);
    } catch {}
    try {
      const v6 = await dns.resolve6(hostname);
      resolvedIps.push(...v6);
    } catch {}

    const matchesLocalIp = resolvedIps.some(ip => localIps.includes(ip));
    if (matchesLocalIp) {
      const portNum = parsedUrl.port
        ? Number(parsedUrl.port)
        : (parsedUrl.protocol === 'https:' ? 443 : 80);
      return portNum === serverPort;
    }
  } catch {
    // DNS error ignored
  }

  return false;
}

function isPrivateIp(ip) {
  return (
    ip.startsWith('10.') ||
    ip.startsWith('172.') ||
    ip.startsWith('192.168.') ||
    ip === '127.0.0.1' ||
    ip === '::1' ||
    ip.startsWith('169.254.') // Link-local (AWS metadata IP)
  );
}

app.use(express.raw({ type: '*/*', limit: '10mb' }));
app.use(cors());

app.all('/proxy', rateLimiter, async (req, res) => {
  try {
    const targetUrl = req.query.url;
    if (!targetUrl || typeof targetUrl !== 'string') {
      return res.status(400).json({ error: 'Missing or invalid ?url=' });
    }

    const parsedUrl = parseUrl(targetUrl);

    // Block forbidden ports
    const targetPort = parsedUrl.port ? Number(parsedUrl.port) : (
      parsedUrl.protocol === 'https:' ? 443 : 80
    );
    if (FORBIDDEN_PORTS.has(targetPort) || targetPort === PORT) {
      return res.status(403).json({ error: 'Port is forbidden' });
    }

    // Block direct private IPs
    if (net.isIP(parsedUrl.hostname) && isPrivateIp(parsedUrl.hostname)) {
      return res.status(403).json({ error: 'Direct IP to private range is forbidden' });
    }

    // Block self requests
    if (await isRequestToSelf(parsedUrl, PORT)) {
      return res.status(403).json({ error: 'Request to proxy server itself is forbidden' });
    }

    // Resolve IPs and block private ones
    try {
      const resolved4 = await dns.resolve4(parsedUrl.hostname);
      const resolved6 = await dns.resolve6(parsedUrl.hostname).catch(() => []);
      const allIps = [...resolved4, ...resolved6];
      if (allIps.some(ip => isPrivateIp(ip))) {
        return res.status(403).json({ error: 'Resolved IP is private — blocked' });
      }
    } catch {
      return res.status(403).json({ error: 'Could not resolve target host' });
    }

    // Prevent proxy loops
    if (req.headers['x-proxy-hop']) {
      return res.status(400).json({ error: 'Proxy loop detected' });
    }

    const headers = { ...req.headers };
    delete headers['host'];
    headers['x-proxy-hop'] = '1';

    const fetchOptions = {
      method: req.method,
      headers,
      redirect: 'follow',
      signal: AbortSignal.timeout(15000),
      body: ['GET', 'HEAD'].includes(req.method.toUpperCase()) ? undefined : req.body
    };

    const fetchResponse = await fetchFunc(targetUrl, fetchOptions);

    fetchResponse.headers.forEach((value, key) => {
      res.setHeader(key, value);
    });
    res.setHeader('access-control-allow-origin', '*');

    res.status(fetchResponse.status);
    fetchResponse.body.pipe(res);
  } catch (err) {
    res.status(500).json({ error: 'Proxy error', details: err.message });
  }
});

app.listen(PORT, '0.0.0.0', () => {
  console.log(`Hardened CORS proxy listening on http://0.0.0.0:${PORT}`);
});
