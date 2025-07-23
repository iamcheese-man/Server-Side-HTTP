import express from 'express';
import fetch from 'node-fetch';
import cors from 'cors';
import dns from 'dns/promises';

const app = express();
const PORT = process.env.PORT || 5000;

// CORS freedom
app.use(cors({
  origin: '*',
  methods: '*',
  allowedHeaders: '*',
  credentials: false
}));

app.use(express.json({ limit: '1000mb' }));
app.use(express.raw({ limit: '1000mb', type: '*/*' }));
app.use(express.text({ limit: '1000mb', type: 'text/*' }));
app.use(express.urlencoded({ extended: true, limit: '1000mb' }));

// Preflight handler
app.options('*', (req, res) => {
  res.header('Access-Control-Allow-Origin', '*');
  res.header('Access-Control-Allow-Methods', '*');
  res.header('Access-Control-Allow-Headers', '*');
  res.header('Access-Control-Max-Age', '86400');
  res.sendStatus(200);
});

app.get('/', (req, res) => res.send('Server is alive'));

// Check for private IPs
function isPrivateIp(ip) {
  const privateRanges = [
    /^127\./,
    /^10\./,
    /^172\.(1[6-9]|2[0-9]|3[0-1])\./,
    /^192\.168\./
  ];
  const privateIPv6Ranges = [
    /^::1$/,
    /^fc00:/i
  ];
  return privateRanges.some(r => r.test(ip)) || privateIPv6Ranges.some(r => r.test(ip));
}

app.all('/proxy', async (req, res) => {
  try {
    const url = req.body?.url || req.query.url || req.headers['x-target-url'];
    const method = req.body?.method || req.query.method || req.headers['x-target-method'] || req.method;
    const customHeaders = req.body?.headers || req.query.headers || {};
    let body = req.body?.body || req.query.body;

    if (!url) return res.status(400).json({ error: 'URL required' });

    // --- Prevent recursive proxying (loop protection) ---
    if (req.headers['x-proxy-hop']) {
      return res.status(400).json({ error: 'Recursive proxy call detected and blocked' });
    }

    let hostname;
    try {
      hostname = new URL(url).hostname;
    } catch {
      return res.status(400).json({ error: 'Invalid URL' });
    }

    // --- Prevent proxy calling itself via domain or localhost ---
    const parsedUrl = new URL(url);
    const isSelfDomain =
      parsedUrl.hostname === req.hostname ||
      parsedUrl.hostname === 'localhost' ||
      parsedUrl.hostname === '127.0.0.1' ||
      parsedUrl.hostname === '::1';

    const isSelfProxyCall = isSelfDomain && parsedUrl.pathname === '/proxy';
    if (isSelfProxyCall) {
      return res.status(403).json({ error: 'Request to proxy endpoint from itself is forbidden' });
    }

    // DNS resolution
    let addresses;
    try {
      addresses = await dns.lookup(hostname, { all: true });
    } catch (dnsErr) {
      return res.status(400).json({ error: 'DNS lookup failed', details: dnsErr.message });
    }

    if (addresses.some(addr => isPrivateIp(addr.address))) {
      return res.status(403).json({ error: 'Access to localhost or private IP ranges is forbidden' });
    }

    // Forward headers
    const forwardHeaders = { ...customHeaders };

    Object.keys(req.headers).forEach(key => {
      if (!['host', 'connection', 'content-length', 'transfer-encoding'].includes(key.toLowerCase())) {
        if (!forwardHeaders[key]) {
          forwardHeaders[key] = req.headers[key];
        }
      }
    });

    // Inject loop protection header
    forwardHeaders['X-Proxy-Hop'] = '1';

    const options = {
      method: method.toUpperCase(),
      headers: forwardHeaders
    };

    if (body && !['GET', 'HEAD', 'OPTIONS'].includes(options.method)) {
      if (typeof body === 'object' && body !== null) {
        options.body = JSON.stringify(body);
        if (!options.headers['Content-Type']) {
          options.headers['Content-Type'] = 'application/json';
        }
      } else {
        options.body = body;
      }
    } else if (req.rawBody && !['GET', 'HEAD', 'OPTIONS'].includes(options.method)) {
      options.body = req.rawBody;
    }

    const response = await fetch(url, options);

    const responseHeaders = {};
    response.headers.forEach((value, key) => {
      responseHeaders[key] = value;
    });

    const buffer = await response.arrayBuffer();
    const responseBody = Buffer.from(buffer);

    res.header('Access-Control-Allow-Origin', '*');
    res.header('Access-Control-Allow-Methods', '*');
    res.header('Access-Control-Allow-Headers', '*');
    res.header('Access-Control-Expose-Headers', '*');

    Object.keys(responseHeaders).forEach(key => {
      if (!['transfer-encoding', 'connection', 'content-encoding'].includes(key.toLowerCase())) {
        res.header(key, responseHeaders[key]);
      }
    });

    res.status(response.status).json({
      status: response.status,
      statusText: response.statusText,
      headers: responseHeaders,
      body: responseBody.toString(),
      url: url,
      method: method.toUpperCase()
    });

  } catch (error) {
    res.status(500).json({ error: error.message, stack: error.stack });
  }
});

app.use('*', (req, res) => {
  res.status(404).json({
    error: 'Endpoint not found',
    hint: 'Use /proxy with url parameter'
  });
});

app.listen(PORT, '0.0.0.0', () => {
  console.log(`CORS Freedom Proxy running on port ${PORT}`);
  console.log('All HTTP methods supported - complete freedom!');
});
