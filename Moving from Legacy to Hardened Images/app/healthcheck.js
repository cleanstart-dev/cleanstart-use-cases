// Internal HTTP healthcheck — replaces `curl` in HEALTHCHECK
// Exits 0 on 2xx, 1 otherwise.
const http = require('http');
const port = process.env.PORT || 3000;
const req = http.get(`http://127.0.0.1:${port}/healthz`, (res) => {
  process.exit(res.statusCode >= 200 && res.statusCode < 300 ? 0 : 1);
});
req.on('error', () => process.exit(1));
req.setTimeout(2000, () => { req.destroy(); process.exit(1); });