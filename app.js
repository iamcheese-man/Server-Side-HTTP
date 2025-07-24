import express from 'express';
import fetch from 'node-fetch';
import cors from 'cors';
import dns from 'dns/promises';
import os from 'os';

const app = express();
const PORT = process.env.PORT || 54839;

// Capture raw body middleware
app.use((req, res, next) => {
  const chunks = [];
  req.on('data', chunk => chunks.push(chunk));
  req.on('end', () => {
    req.rawBody = Buffer.concat(chunks);
    next();
  });
});

// CORS setup
app.use(cors({
  origin: '*',
  credentials: false,
  methods: ['GET','POST','PUT','DELETE','PATCH','OPTIONS','HEAD'],
  allowedHeaders: (req, callback) => {
    const reqHeaders = req.headers['access-control-request-headers'];
    callback(null, reqHeaders ? reqHeaders.split(',').map(h => h.trim()) : ['Content-Type', 'Authorization']);
  }
}));

app.use(express.json({ limit: '1000mb' }));
app.use(express.urlencoded({ extended: true, limit: '1000mb' }));
app.use(express.text({ type: 'text/*', limit: '1000mb' }));
app.use(express.raw({ type: '*/*', limit: '1000mb' }));

app.options('*', (req, res) => {
  res.header('Access-Control-Allow-Origin', '*');
  res.header('Access-Control-Allow-Methods', req.headers['access-control-request-method'] || '*');
  res.header('Access-Control-Allow-Headers', req.headers['access-control-request-headers'] || '*');
  res.header('Access-Control-Max-Age', '86400');
  res.sendStatus(200);
});

app.get('/', (req, res) => res.send('Server is alive'));

const localIps = Object.values(os.networkInterfaces())
  .flat()
  .filter(Boolean)
  .map(i => i.address);

const forbiddenPorts = [22, 2375, 3306, 6379, 5000, 8000];

function isPrivateIp(ip) {
  const privateRanges = [
    /^127\./,
    /^10\./,
    /^172\.(1[6-9]|2[0-9]|3[0-1])\./,
    /^192\.168\./
  ];
  const privateIPv6Ranges = [
    /^::1$/,
    /^fc00:/i,
    /^fd00:/i
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

    if (req.headers['x-proxy-hop']) {
      return res.status(400).json({ error: 'Recursive proxy call detected and blocked' });
    }

    let parsedUrl;
    try {
      parsedUrl = new URL(url);
    } catch {
      return res.status(400).json({ error: 'Invalid URL' });
    }

    // ✅ Block sensitive/dangerous protocols
    const forbiddenProtocols = ['file:', 'data:', 'javascript:', 'about:', 'ftp:', 'ws:', 'wss:'];
    if (forbiddenProtocols.includes(parsedUrl.protocol)) {
      return res.status(403).json({ error: `${parsedUrl.protocol} protocol is forbidden` });
    }

    // ✅ Block sensitive ports
    const port = parsedUrl.port ? parseInt(parsedUrl.port) : (parsedUrl.protocol === 'https:' ? 443 : 80);
    if (forbiddenPorts.includes(port)) {
      return res.status(403).json({ error: `Access to port ${port} is forbidden` });
    }

    let addresses;
    try {
      addresses = await dns.lookup(parsedUrl.hostname, { all: true });
    } catch (dnsErr) {
      return res.status(400).json({ error: 'DNS lookup failed', details: dnsErr.message });
    }

    if (addresses.some(addr => isPrivateIp(addr.address) || localIps.includes(addr.address))) {
      return res.status(403).json({ error: 'Access to internal or server IPs is forbidden' });
    }

    if (parsedUrl.pathname === '/proxy') {
      return res.status(403).json({ error: 'Request to proxy endpoint from itself is forbidden' });
    }

    const forwardHeaders = { ...customHeaders };
    Object.keys(req.headers).forEach(key => {
      if (!['host', 'connection', 'content-length', 'transfer-encoding'].includes(key.toLowerCase())) {
        if (!forwardHeaders[key]) forwardHeaders[key] = req.headers[key];
      }
    });
    forwardHeaders['X-Proxy-Hop'] = '1';

    const options = {
      method: method.toUpperCase(),
      headers: forwardHeaders
    };

    if (body && !['GET', 'HEAD', 'OPTIONS'].includes(options.method)) {
      if (typeof body === 'object' && body !== null) {
        options.body = JSON.stringify(body);
        if (!options.headers['Content-Type']) options.headers['Content-Type'] = 'application/json';
      } else {
        options.body = body;
      }
    } else if (req.rawBody && !['GET', 'HEAD', 'OPTIONS'].includes(options.method)) {
      options.body = req.rawBody;
    }

    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), 15000);
    options.signal = controller.signal;

    let response;
    try {
      response = await fetch(url, options);
      clearTimeout(timeoutId);
    } catch (err) {
      clearTimeout(timeoutId);
      if (err.name === 'AbortError') {
        return res.status(504).json({ error: 'Fetch request timed out' });
      }
      throw err;
    }

    const responseHeaders = {};
    response.headers.forEach((value, key) => {
      responseHeaders[key] = value;
    });

    res.header('Access-Control-Allow-Origin', '*');
    res.header('Access-Control-Allow-Methods', req.headers['access-control-request-method'] || '*');
    res.header('Access-Control-Allow-Headers', req.headers['access-control-request-headers'] || '*');
    res.header('Access-Control-Expose-Headers', '*');

    Object.keys(responseHeaders).forEach(key => {
      if (!['transfer-encoding', 'connection', 'content-encoding'].includes(key.toLowerCase())) {
        res.header(key, responseHeaders[key]);
      }
    });

    const buffer = Buffer.from(await response.arrayBuffer());
    res.status(response.status).send(buffer);

  } catch (error) {
    res.header('Access-Control-Allow-Origin', '*');
    res.header('Access-Control-Allow-Methods', '*');
    res.header('Access-Control-Allow-Headers', '*');
    res.header('Access-Control-Expose-Headers', '*');
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
