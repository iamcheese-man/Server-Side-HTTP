import express from 'express';
import fetch from 'node-fetch';
import cors from 'cors';

const app = express();
const PORT = process.env.PORT || 3000;

app.use(cors()); // Allow all origins, adjust for security in production
app.use(express.json({ limit: '10mb' })); // parse JSON body, increase limit if needed

app.post('/proxy', async (req, res) => {
  try {
    const { url, method = 'GET', headers = {}, body } = req.body;

    if (!url) return res.status(400).json({ error: 'Missing URL' });

    // Build fetch options
    const options = {
      method: method.toUpperCase(),
      headers,
    };

    if (body && method.toUpperCase() !== 'GET' && method.toUpperCase() !== 'HEAD') {
      options.body = typeof body === 'string' ? body : JSON.stringify(body);
      // Add content-type if not present and body is JSON
      if (!headers['Content-Type'] && !headers['content-type']) {
        options.headers['Content-Type'] = 'application/json';
      }
    }

    const response = await fetch(url, options);

    // Gather response headers
    const responseHeaders = {};
    response.headers.forEach((value, key) => {
      responseHeaders[key] = value;
    });

    // Get response body as text
    const responseBody = await response.text();

    // Send back status, headers and body
    res.json({
      status: response.status,
      statusText: response.statusText,
      headers: responseHeaders,
      body: responseBody,
    });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.listen(PORT, () => {
  console.log(`Proxy server running on port ${PORT}`);
});
