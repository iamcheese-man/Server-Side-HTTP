import express from 'express';
import fetch from 'node-fetch';
import cors from 'cors';
import { URL } from 'url';
import dns from 'dns/promises';

const app = express();
const PORT = process.env.PORT || 5000;

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

app.options('*', (req, res) => {
  res.header('Access-Control-Allow-Origin', '*');
  res.header('Access-Control-Allow-Methods', '*');
  res.header('Access-Control-Allow-Headers', '*');
  res.header('Access-Control-Max-Age', '86400');
  res.sendStatus(200);
});

app.get('/', (req, res) => res.send('Server is alive'));

// 🔐 Security: Block localhost/private IP targets
function isPrivateAddress(ip) {
  return (
    ip.startsWith('127.') ||
    ip === '::1' ||
    ip === 'localhost' ||
    ip.startsWith('10.') ||
    ip.startsWith('192.168.') ||
    /^172\.(1[6-9]|2[0-9]|3[0-1])\./.test(ip)
  );
}

app.all('/proxy', async (req, res) => {
  try {
    const url = req.body?.url || req.query.url || req.headers['x-target-url'];
    const method = req.body?.method || req.query.method || req.headers['x-target-method'] || req.method;
    const customHeaders = req.body?.headers || req.query.headers || {};
    let body = req.body?.body || req.query.body;

    if (!url) {
      return res.status(400).json({ error: 'URL required' });
    }

    // 🛡️ Block localhost/private IPs
    const parsedUrl = new URL(url);
    const hostname = parsedUrl.hostname;

    const addresses = await dns.lookup(hostname, { all: true });
    for (const addr of addresses) {
      if (isPrivateAddress(addr.address)) {
        return res.status(403).json({ error: 'Access to private or local IPs is blocked.' });
      }
    }

    const forwardHeaders = { ...customHeaders };
    Object.keys(req.headers).forEach(key => {
      if (!['host', 'connection', 'content-length', 'transfer-encoding'].includes(key.toLowerCase())) {
        if (!forwardHeaders[key]) {
          forwardHeaders[key] = req.headers[key];
        }
      }
    });

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
    res.status(500).json({ 
      error: error.message,
      stack: error.stack
    });
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
});
