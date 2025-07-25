// This version is PURELY designed for private use. If exposed publicly, hackers can abuse the proxy.
const http = require('http');
const net = require('net');
const url = require('url');
const httpProxy = require('http-proxy');

const proxy = httpProxy.createProxyServer({});

// Add wildcard CORS headers on proxied responses
proxy.on('proxyRes', (proxyRes, req, res) => {
  proxyRes.headers['Access-Control-Allow-Origin'] = '*';
  proxyRes.headers['Access-Control-Allow-Methods'] = '*';
  proxyRes.headers['Access-Control-Allow-Headers'] = '*';
});

const server = http.createServer((req, res) => {
  // Proxy all normal HTTP methods transparently
  proxy.web(req, res, { target: req.url, changeOrigin: true }, err => {
    res.writeHead(502);
    res.end(`Proxy error: ${err.message}`);
  });
});

// Handle HTTPS tunneling via CONNECT
server.on('connect', (req, clientSocket, head) => {
  const { hostname, port } = url.parse(`http://${req.url}`);

  const serverSocket = net.connect(port || 443, hostname, () => {
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

const PORT = 8080;
server.listen(PORT, () => {
  console.log(`Full protocols, full methods HTTP proxy listening on port ${PORT}`);
});
