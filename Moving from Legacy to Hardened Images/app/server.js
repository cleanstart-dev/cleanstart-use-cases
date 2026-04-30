// receipt-api: minimal Express service used to demonstrate
// behavioral parity between legacy and hardened images.
const express = require('express');
const app = express();
app.use(express.json());

const PORT = parseInt(process.env.PORT || '3000', 10);

app.get('/healthz', (req, res) => {
  res.status(200).json({ status: 'ok', uptime: process.uptime() });
});

app.get('/ready', (req, res) => {
  res.status(200).json({ ready: true });
});

app.post('/receipt', (req, res) => {
  const { amount, currency, customer } = req.body || {};
  if (!amount || !currency) {
    return res.status(400).json({ error: 'amount and currency required' });
  }
  res.status(201).json({
    id: `rcpt_${Date.now()}`,
    amount,
    currency,
    customer: customer || 'anonymous',
    createdAt: new Date().toISOString(),
  });
});

const server = app.listen(PORT, () => {
  console.log(`receipt-api listening on :${PORT} (uid=${process.getuid?.() ?? 'n/a'})`);
});

// Graceful shutdown — Barrier 7 fix
process.on('SIGTERM', () => {
  console.log('SIGTERM received, draining...');
  server.close(() => process.exit(0));
});
process.on('SIGINT', () => {
  server.close(() => process.exit(0));
});