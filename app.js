import express from 'express';
import fetch from 'node-fetch';
import cors from 'cors';
import dns from 'dns/promises';  // Using promises-based dns module

const app = express();
const PORT = process.env.PORT || 5000;

// Complete CORS freedom
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

// Handle ALL preflight requests
app.options('*', (req, res) => {
  res.header('Access-Control-Allow-Origin', '*');
  res.header('Access-Control-Allow-Methods', '*');
  res.header('Access-Control-Allow-Headers', '*');
  res.header('Access-Control-Max-Age', '86400');
  res.sendStatus(200);
});

app.get('/', (req, res) => res.send('Server is alive'));

// Helper: Check if IP is localhost or private
function isPrivateIp(ip) {
  // IPv4 ranges
  const privateRanges = [
    /^127\./,                 // Loopback IPv4
    /^10\./,                  // Private A
    /^172\.(1[6-9]|2[0-9]|3[0-1])\./,  // Private B
    /^192\.168\./             // Private C
  ];

  // IPv6 localhost and unique local addresses
  const privateIPv6Ranges = [
    /^::1$/,                  // IPv6 localhost
    /^fc00:/i                 // IPv6 unique local address
  ];

  return privateRanges.some(r => r.test(ip)) || privateIPv6Ranges.some(r => r.test(ip));
}

// Support ALL HTTP methods - complete freedom with added security
app.all('/proxy', async (req, res) => {
  try {
    // Get URL from anywhere
    const url = req.body?.url || req.query.url || req.headers['x-target-url'];
    const method = req.body?.method || req.query.method || req.headers['x-target-method'] || req.method;
    const customHeaders = req.body?.headers || req.query.headers || {};
    let body = req.body?.body || req.query.body;

    if (!url) {
      return res.status(400).json({ error: 'URL required' });
    }

    // Parse hostname from URL to check for private IPs
    let hostname;
    try {
      hostname = new URL(url).hostname;
    } catch {
      return res.status(400).json({ error: 'Invalid URL' });
    }

    // DNS lookup to get IPs
    let addresses;
    try {
      addresses = await dns.lookup(hostname, { all: true });
    } catch (dnsErr) {
      return res.status(400).json({ error: 'DNS lookup failed', details: dnsErr.message });
    }

    // Check all resolved IPs against private ranges
    if (addresses.some(addr => isPrivateIp(addr.address))) {
      return res.status(403).json({ error: 'Access to localhost or private IP ranges is forbidden' });
    }

    // Prepare headers - forward everything except problematic ones
    const forwardHeaders = { ...customHeaders };
    
    // Copy original request headers if needed
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

    // Handle body for methods that support it
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

    // Make the request with complete freedom
    const response = await fetch(url, options);

    // Capture ALL response headers
    const responseHeaders = {};
    response.headers.forEach((value, key) => {
      responseHeaders[key] = value;
    });

    // Get response body as buffer
    const buffer = await response.arrayBuffer();
    const responseBody = Buffer.from(buffer);

    // Set permissive CORS headers
    res.header('Access-Control-Allow-Origin', '*');
    res.header('Access-Control-Allow-Methods', '*');
    res.header('Access-Control-Allow-Headers', '*');
    res.header('Access-Control-Expose-Headers', '*');

    // Forward response headers from target (except problematic ones)
    Object.keys(responseHeaders).forEach(key => {
      if (!['transfer-encoding', 'connection', 'content-encoding'].includes(key.toLowerCase())) {
        res.header(key, responseHeaders[key]);
      }
    });

    // Return response with complete data
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

// Catch-all route for maximum flexibility
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
