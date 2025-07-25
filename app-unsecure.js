// This version is PURELY designed for private use. If exposed publicly, hackers can abuse the proxy.
const http = require('http');
const net = require('net');
const httpProxy = require('http-proxy');

const proxy = httpProxy.createProxyServer({});

// Add permissive CORS headers on proxied responses
proxy.on('proxyRes', (proxyRes, req, res) => {
  proxyRes.headers['Access-Control-Allow-Origin'] = '*';
  proxyRes.headers['Access-Control-Allow-Methods'] = '*';
  proxyRes.headers['Access-Control-Allow-Headers'] = '*';
});

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

  // Accept relative URLs by prefixing with host header
  const target = req.url.startsWith('http') ? req.url : `http://${req.headers.host}${req.url}`;

  proxy.web(req, res, { target, changeOrigin: true }, err => {
    console.error('Proxy error:', err);
    res.writeHead(200);
    res.end('');
  });
});

server.on('connect', (req, clientSocket, head) => {
  const [host, port] = req.url.split(':');

  const serverSocket = net.connect(port || 443, host, () => {
    clientSocket.write('HTTP/1.1 200 Connection Established\r\n\r\n');
    serverSocket.write(head);
    serverSocket.pipe(clientSocket);
    clientSocket.pipe(serverSocket);
  });

  serverSocket.on('error', err => {
    clientSocket.write(`HTTP/1.1 502 Bad Gateway\r\n\r\n${err.message}`);
    clientSocket.end();
  });

  clientSocket.on('error', () => {
    serverSocket.end();
  });
});

// Support WebSocket proxying
server.on('upgrade', (req, socket, head) => {
  const target = req.url.startsWith('http') ? req.url : `http://${req.headers.host}${req.url}`;
  proxy.ws(req, socket, head, { target, changeOrigin: true }, err => {
    console.error('WebSocket proxy error:', err);
    socket.end();
  });
});

server.timeout = 0;

const PORT = 8080;
server.listen(PORT, '127.0.0.1', () => {
  console.log(`Ultra-free local proxy listening on 127.0.0.1:${PORT}`);
});
