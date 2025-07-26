// This version is PURELY designed for private use. If exposed publicly, hackers can abuse the proxy.
const http = require('http');
const net = require('net');
const httpProxy = require('http-proxy');

const proxy = httpProxy.createProxyServer({ changeOrigin: true });

// Add wildcard CORS headers to all proxy responses
proxy.on('proxyRes', (proxyRes) => {
  proxyRes.headers['Access-Control-Allow-Origin'] = '*';
  proxyRes.headers['Access-Control-Allow-Methods'] = '*';
  proxyRes.headers['Access-Control-Allow-Headers'] = '*';
});

// Main HTTP server
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

  const target = req.url.startsWith('http') ? req.url : `http://${req.headers.host}${req.url}`;
  proxy.web(req, res, { target }, (err) => {
    res.writeHead(502, { 'Content-Type': 'text/plain' });
    res.end('Proxy error: ' + err.message);
  });
});

// HTTPS and raw TCP via CONNECT
server.on('connect', (req, clientSocket, head) => {
  const [host, port] = req.url.split(':');
  const serverSocket = net.connect(port || 443, host, () => {
    clientSocket.write('HTTP/1.1 200 Connection Established\r\n\r\n');
    if (head && head.length) serverSocket.write(head);
    clientSocket.pipe(serverSocket);
    serverSocket.pipe(clientSocket);
  });

  serverSocket.on('error', (err) => {
    clientSocket.write(`HTTP/1.1 502 Bad Gateway\r\n\r\n${err.message}`);
    clientSocket.end();
  });

  clientSocket.on('error', () => serverSocket.end());
});

// WebSocket proxying
server.on('upgrade', (req, socket, head) => {
  const target = req.url.startsWith('http') ? req.url : `http://${req.headers.host}${req.url}`;
  proxy.ws(req, socket, head, { target }, (err) => {
    socket.end();
  });
});

// No timeout
server.timeout = 0;

const PORT = 8080;
server.listen(PORT, '127.0.0.1', () => {
  console.log(`🚀 All-Protocol Proxy running at http://127.0.0.1:${PORT}`);
});
