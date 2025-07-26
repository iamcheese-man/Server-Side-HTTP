// This version is PURELY designed for private use. If exposed publicly, hackers can abuse the proxy.
const http = require('http');
const net = require('net');
const httpProxy = require('http-proxy');
const url = require('url');

const proxy = httpProxy.createProxyServer({
  changeOrigin: true,
  secure: false, // allow self-signed certs
});

// Add full wildcard CORS to all proxy responses
proxy.on('proxyRes', (proxyRes) => {
  proxyRes.headers['Access-Control-Allow-Origin'] = '*';
  proxyRes.headers['Access-Control-Allow-Methods'] = '*';
  proxyRes.headers['Access-Control-Allow-Headers'] = '*';
});

// Main HTTP handler
const server = http.createServer((req, res) => {
  if (req.method === 'OPTIONS') {
    res.writeHead(204, {
      'Access-Control-Allow-Origin': '*',
      'Access-Control-Allow-Methods': '*',
      'Access-Control-Allow-Headers': '*',
      'Access-Control-Max-Age': 86400,
    });
    return res.end();
  }

  try {
    let fullTarget;

    // If ?url= query parameter exists, use it, else fallback to original path logic
    const query = url.parse(req.url, true).query;
    if (query.url) {
      fullTarget = query.url;
    } else {
      const parsedUrl = url.parse(req.url.slice(1)); // strip leading slash
      if (!parsedUrl.protocol || !parsedUrl.host) throw new Error('Invalid URL');
      fullTarget = parsedUrl.href;
    }

    proxy.web(req, res, { target: fullTarget }, (err) => {
      res.writeHead(502, { 'Content-Type': 'text/plain' });
      res.end('Proxy error: ' + err.message);
    });
  } catch (err) {
    res.writeHead(400, { 'Content-Type': 'text/plain' });
    res.end('Bad proxy request: ' + err.message);
  }
});

// CONNECT tunneling (for HTTPS)
server.on('connect', (req, clientSocket, head) => {
  const [host, port] = req.url.split(':');
  const serverSocket = net.connect(port || 443, host, () => {
    clientSocket.write('HTTP/1.1 200 Connection Established\r\n\r\n');
    if (head.length) serverSocket.write(head);
    clientSocket.pipe(serverSocket);
    serverSocket.pipe(clientSocket);
  });

  serverSocket.on('error', (err) => {
    clientSocket.write(`HTTP/1.1 502 Bad Gateway\r\n\r\n${err.message}`);
    clientSocket.end();
  });

  clientSocket.on('error', () => serverSocket.end());
});

// WebSocket upgrade support
server.on('upgrade', (req, socket, head) => {
  try {
    let fullTarget;

    const query = url.parse(req.url, true).query;
    if (query.url) {
      fullTarget = query.url;
    } else {
      const parsedUrl = url.parse(req.url.slice(1));
      fullTarget = parsedUrl.href;
    }

    proxy.ws(req, socket, head, { target: fullTarget }, () => socket.end());
  } catch {
    socket.end();
  }
});

// No timeout
server.timeout = 0;

const PORT = 8080;
server.listen(PORT, '127.0.0.1', () => {
  console.log(`🧪 Local All-Access Proxy running on http://127.0.0.1:${PORT}`);
});
