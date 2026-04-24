// src/server.js
// FinTrack API - Demo server showing transitive vulnerability exposure
// This server has INTENTIONAL vulnerabilities for educational purposes.

const express = require('express');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');

const app = express();

// Middleware
app.use(helmet());
app.use(express.json());

const limiter = rateLimit({ windowMs: 15 * 60 * 1000, max: 100 });
app.use(limiter);

// --- Routes ---

// Simulated bank accounts endpoint
app.get('/api/accounts/:userId', (req, res) => {
  const { userId } = req.params;
  res.json({
    userId,
    accounts: [
      { id: 'acc_001', type: 'checking', balance: 4250.00 },
      { id: 'acc_002', type: 'savings',  balance: 12800.50 },
    ],
  });
});

// Simulated transaction fetch (uses axios internally)
app.get('/api/transactions', async (req, res) => {
  try {
    res.json({ message: 'Transactions endpoint active', note: 'axios@1.4.0 with vulnerable follow-redirects' });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Health check
app.get('/health', (req, res) => {
  res.json({ status: 'ok', version: '2.3.1' });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`FinTrack API running on http://localhost:${PORT}`);
  console.log(`\nRun: npm run scan:layers  — to see the two-layer vulnerability model`);
  console.log(`Run: npm run scan:tree    — to trace CVEs to their source`);
  console.log(`Run: npm run demo         — to see the ReDoS risk demo`);
});
