// This app.js version allows everyone on your same Wi-Fi network to use the proxy.
import express from 'express';
import os from 'os';
import dns from 'dns/promises';
import cors from 'cors';
import net from 'net';
import { parse as parseUrl } from 'url';
import os from 'os';

function getLocalIP() {
  const nets = os.networkInterfaces();
  for (const name in nets) {
    for (const net of nets[name]) {
      if (net.family === 'IPv4' && !net.internal) {
        return net.address;
      }
    }
  }
  return '127.0.0.1'; // fallback
}
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

app.use(express.raw({ type: '*/*', limit: '1000mb' }));
app.use(cors());

app.all('/proxy', async (req, res) => {
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

    // Block direct private IPs (no DNS involved)
    if (net.isIP(parsedUrl.hostname) && isPrivateIp(parsedUrl.hostname)) {
      return res.status(403).json({ error: 'Direct IP to private range is forbidden' });
    }

    // Block self requests
    if (await isRequestToSelf(parsedUrl, PORT)) {
      return res.status(403).json({ error: 'Request to proxy server itself is forbidden' });
    }

    // Resolve and ensure all IPs are public (stop DNS rebinding)
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
app.on('connect', async (req, clientSocket, head) => {
  try {
    // Extract hostname and port from req.url, e.g. "example.com:443"
    const [host, portStr] = req.url.split(':');
    const port = Number(portStr) || 443;

    // Basic validations:
    if (FORBIDDEN_PORTS.has(port) || port === PORT) {
      clientSocket.write(`HTTP/1.1 403 Forbidden\r\n\r\n`);
      clientSocket.destroy();
      return;
    }

    // Block direct private IPs
    if (net.isIP(host) && isPrivateIp(host)) {
      clientSocket.write(`HTTP/1.1 403 Forbidden\r\n\r\n`);
      clientSocket.destroy();
      return;
    }

    // Block localhost/self requests
    const dummyUrl = `http://${host}:${port}`;
    const parsedUrl = parseUrl(dummyUrl);

    if (await isRequestToSelf(parsedUrl, PORT)) {
      clientSocket.write(`HTTP/1.1 403 Forbidden\r\n\r\n`);
      clientSocket.destroy();
      return;
    }

    // Resolve hostname and check IPs (stop DNS rebinding)
    let resolvedIps = [];
    try {
      const v4 = await dns.resolve4(host);
      resolvedIps.push(...v4);
    } catch {}
    try {
      const v6 = await dns.resolve6(host);
      resolvedIps.push(...v6);
    } catch {}

    if (resolvedIps.length === 0 || resolvedIps.some(ip => isPrivateIp(ip))) {
      clientSocket.write(`HTTP/1.1 403 Forbidden\r\n\r\n`);
      clientSocket.destroy();
      return;
    }

    // Establish TCP connection to target
    const serverSocket = net.connect(port, host, () => {
      // HTTP/1.1 200 Connection Established
      clientSocket.write('HTTP/1.1 200 Connection Established\r\n\r\n');

      // Pipe data both ways
      serverSocket.write(head);
      clientSocket.pipe(serverSocket);
      serverSocket.pipe(clientSocket);
    });

    // Error handling
    serverSocket.on('error', () => {
      clientSocket.write('HTTP/1.1 502 Bad Gateway\r\n\r\n');
      clientSocket.destroy();
    });

    clientSocket.on('error', () => {
      serverSocket.destroy();
    });

  } catch {
    clientSocket.write(`HTTP/1.1 500 Internal Server Error\r\n\r\n`);
    clientSocket.destroy();
  }
});
const localIP = getLocalIP();
app.listen(PORT, localIP, () => {
  console.log(`CORS Freedom Proxy running on port ${PORT}, and running on server: ${os.hostname()} (${os.platform()})`);
  console.log('All HTTP methods supported - complete freedom!');
});
