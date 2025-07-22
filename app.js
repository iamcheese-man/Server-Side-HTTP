import express from 'express';
import fetch from 'node-fetch';
import cors from 'cors';

const app = express();
const PORT = process.env.PORT || 5000;

app.use(cors());
app.use(express.json({ limit: '1000mb' }));

app.get('/', (req, res) => res.send('Server is alive'));

app.all('/proxy', async (req, res) => {
  try {
    const { url, method = req.method, headers = {}, body } = req.body || {};
    if (!url) return res.status(400).json({ error: 'Missing URL' });

    const options = {
      method: method.toUpperCase(),
      headers: { ...headers }
    };

    if (body && !['GET', 'HEAD'].includes(options.method)) {
      options.body = typeof body === 'string' ? body : JSON.stringify(body);
      if (!options.headers['Content-Type'] && !options.headers['content-type']) {
        options.headers['Content-Type'] = 'application/json';
      }
    }

    const response = await fetch(url, options);

    const responseHeaders = {};
    response.headers.forEach((value, key) => {
      responseHeaders[key] = value;
    });

    const responseBody = await response.text();

    res.json({
      status: response.status,
      statusText: response.statusText,
      headers: responseHeaders,
      body: responseBody
    });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.listen(PORT, () => {
  console.log(`Proxy server running on port ${PORT}`);
});
