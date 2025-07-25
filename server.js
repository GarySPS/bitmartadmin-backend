const express = require('express');
const cors = require('cors');
const jwt = require('jsonwebtoken');
const axios = require('axios');
require('dotenv').config();
console.log("LOADED ADMIN_PASSWORD:", process.env.ADMIN_PASSWORD);
const pool = require('./db');
const path = require('path');
const multer = require('multer');
const upload = multer({ dest: path.join(__dirname, '../../novachain-backend/uploads') });

const app = express();
const PORT = 5001;
const fs = require('fs');

const ADMIN_EMAIL = process.env.ADMIN_EMAIL || 'admin@novachain.com';
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || 'SuperSecret123';
const JWT_SECRET = process.env.JWT_SECRET || 'your_jwt_secret';

const MAIN_BACKEND_URL = 'https://novachain-backend.onrender.com';

const userAutoWin = {};
let AUTO_WINNING = true;

const allowedOrigins = [
  'http://localhost:3000',
  'http://localhost:5173',
  'http://localhost:3001',
  'https://www.adminnovachain.link',
  'https://adminnovachain.link'
];

const corsOptions = {
  origin: function (origin, callback) {
    // Allow REST tools without origin (Postman)
    if (!origin) return callback(null, true);
    if (allowedOrigins.includes(origin)) {
      return callback(null, true);
    } else {
      return callback(new Error('CORS Not Allowed: ' + origin));
    }
  },
  credentials: true,
  optionsSuccessStatus: 200
};

app.use(cors(corsOptions));
app.use(express.json());
app.use('/uploads', express.static(path.join(__dirname, '../../novachain-backend/uploads')));

// ===== JWT admin auth middleware =====
function requireAdminAuth(req, res, next) {
  const token = req.headers.authorization && req.headers.authorization.split(' ')[1];
  if (!token) return res.status(401).json({ message: 'No token provided' });
  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    req.adminRole = decoded.role;
    req.adminEmail = decoded.email;
    next();
  } catch {
    res.status(401).json({ message: 'Invalid token' });
  }
}

// ===== NEW: Superadmin only middleware =====
function requireSuperAdmin(req, res, next) {
  if (req.adminRole !== 'superadmin') {
    return res.status(403).json({ message: 'Only superadmin can access this.' });
  }
  next();
}

// ===== List of admins =====
const ADMINS = [
  {
    email: process.env.ADMIN_EMAIL || 'admin@novachain.com',
    password: process.env.ADMIN_PASSWORD || 'SuperSecret123',
    role: 'superadmin', // can access everything
  },
  {
    email: process.env.SUPPORT_EMAIL || 'support@novachain.com',
    password: process.env.SUPPORT_PASSWORD || 'Support123',
    role: 'support', // cannot use deposit settings
  },
];

// ====== PROXY ROUTES (no change) ======
app.get('/api/trades', requireAdminAuth, async (req, res) => {
  try {
    const r = await axios.get(`${MAIN_BACKEND_URL}/api/trades`, {
      headers: { 'x-admin-token': process.env.ADMIN_API_TOKEN }
    });
    res.json(r.data);
  } catch (err) {
    console.error("TRADES PROXY ERROR:", err.response?.data || err.message, err.response?.status || "");
    res.status(500).json({ message: 'Failed to fetch trades', detail: err.message });
  }
});

app.get('/api/deposits', requireAdminAuth, async (req, res) => {
  try {
    const r = await axios.get(`${MAIN_BACKEND_URL}/api/deposits`, {
      headers: { 'x-admin-token': process.env.ADMIN_API_TOKEN }
    });
    res.json(r.data);
  } catch (err) {
    res.status(500).json({ message: 'Failed to fetch deposits', detail: err.message });
  }
});

app.get('/api/withdrawals', requireAdminAuth, async (req, res) => {
  try {
    const r = await axios.get(`${MAIN_BACKEND_URL}/api/withdrawals`, {
      headers: { 'x-admin-token': process.env.ADMIN_API_TOKEN }
    });
    res.json(r.data);
  } catch (err) {
    res.status(500).json({ message: 'Failed to fetch withdrawals', detail: err.message });
  }
});

// ===== NORMAL ADMIN CONTROLS (NOT PROXIED) =====

// --- Admin login
app.post('/api/admin/login', (req, res) => {
  const { email, password } = req.body;
  const admin = ADMINS.find(a => a.email === email && a.password === password);
  if (!admin) {
    return res.status(401).json({ message: 'Invalid email or password' });
  }
  const token = jwt.sign({ email: admin.email, role: admin.role }, JWT_SECRET, { expiresIn: '1h' });
  res.json({ token, role: admin.role }); // send role to frontend too!
});

// --- RESTRICTED: Wallet Settings (Deposit Address) Routes ---
app.post(
  '/api/admin/deposit-addresses',
  requireAdminAuth,
  requireSuperAdmin, // <-- superadmin only!
  upload.any(),
  async (req, res) => {
    try {
      const coins = ['USDT', 'BTC', 'ETH', 'TON', 'SOL', 'XRP'];
      let updated = 0;
      for (const coin of coins) {
        const address = req.body[`${coin}_address`] || '';
        let qr_url = null;
        const qrFile = (req.files || []).find(f => f.fieldname === `${coin}_qr`);
        if (qrFile) {
          qr_url = `/uploads/${qrFile.filename}`;
        }
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
      res.status(500).json({ success: false, message: "Failed to save deposit settings", detail: err.message });
    }
  }
);

app.get(
  '/api/admin/deposit-addresses',
  requireAdminAuth,
  requireSuperAdmin, // <-- superadmin only!
  async (req, res) => {
    try {
      const result = await pool.query(`SELECT coin, address, qr_url FROM deposit_addresses`);
      res.json(result.rows);
    } catch (err) {
      res.status(500).json({ message: "Failed to fetch deposit addresses" });
    }
  }
);

// Fetch users (full info for admin table)
app.get('/api/admin/users', requireAdminAuth, async (req, res) => {
  try {
    // Get users (NO frozen column in users!)
    const usersResult = await pool.query(`
      SELECT id, email, username, created_at, kyc_status, kyc_id_card, kyc_selfie
      FROM users
      ORDER BY id DESC
    `);

    const users = usersResult.rows;

    // Get all balances (frozen is in user_balances!)
    const balancesResult = await pool.query(`
      SELECT user_id, coin, balance, frozen FROM user_balances
    `);
    const balances = balancesResult.rows;

    // Merge balances into users (USDT only)
    const usersWithBalances = users.map(u => {
      const userBalances = balances.filter(b => b.user_id === u.id);
      const usdt = userBalances.find(b => b.coin === "USDT") || {};
      return {
        ...u,
        balance: Number(usdt.balance || 0),
        frozen_balance: Number(usdt.frozen || 0), // from user_balances
      }
    });

    res.json(usersWithBalances);
  } catch (err) {
    console.error("USERS ERROR:", err);
    res.status(500).json({ message: 'Failed to fetch users with balances', detail: err.message });
  }
});

app.delete('/api/admin/user/:id', requireAdminAuth, async (req, res) => {
  const { id } = req.params;
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    await client.query(`DELETE FROM wallets WHERE user_id = $1`, [id]);
    await client.query(`DELETE FROM user_balances WHERE user_id = $1`, [id]);
    await client.query(`DELETE FROM trades WHERE user_id = $1`, [id]);
    await client.query(`DELETE FROM deposits WHERE user_id = $1`, [id]);
    await client.query(`DELETE FROM withdrawals WHERE user_id = $1`, [id]);
    await client.query(`DELETE FROM users WHERE id = $1`, [id]);
    await client.query('COMMIT');
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

// Trade result, user status, etc.
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

// Approve/deny deposit/withdrawal (DO NOT change these - keep local DB logic)
app.post('/api/admin/deposits/:id/approve', requireAdminAuth, async (req, res) => {
  const { id } = req.params;
  try {
    const { rows } = await pool.query(
      'SELECT user_id, amount, coin FROM deposits WHERE id = $1',
      [id]
    );
    if (rows.length === 0) return res.status(404).json({ message: 'Deposit not found' });
    const deposit = rows[0];
    await pool.query(
      'UPDATE deposits SET status = $1 WHERE id = $2',
      ['approved', id]
    );
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
app.post('/api/admin/withdrawals/:id/approve', requireAdminAuth, async (req, res) => {
  const { id } = req.params;
  try {
    const { rows } = await pool.query(
      'SELECT user_id, amount, coin FROM withdrawals WHERE id = $1',
      [id]
    );
    if (rows.length === 0) return res.status(404).json({ message: 'Withdrawal not found' });
    const wd = rows[0];
    await pool.query(
      'UPDATE withdrawals SET status = $1 WHERE id = $2',
      ['approved', id]
    );
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

// TEMP DEBUG ROUTES (optional)
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

// Trade-mode control (proxy to main backend)
app.post('/api/admin/users/:user_id/trade-mode', requireAdminAuth, async (req, res) => {
  const { user_id } = req.params;
  const { mode } = req.body;
  if (!user_id || !['WIN', 'LOSE', null, ""].includes(mode)) {
    return res.status(400).json({ message: 'Invalid input' });
  }
  try {
    const axiosRes = await axios.post(
  `${MAIN_BACKEND_URL}/api/admin/users/${user_id}/trade-mode`,
  { mode: mode || null },
  {
    headers: { 'x-admin-token': process.env.ADMIN_API_TOKEN }
  }
);

    res.json({ success: true, ...axiosRes.data });
  } catch (err) {
    res.status(500).json({ message: 'Failed to update user mode', detail: err.message });
  }
});

// === Manual Balance Add ===
app.post('/api/admin/add-balance', requireAdminAuth, async (req, res) => {
  const { user_id, coin, amount } = req.body;
  if (!user_id || !coin || !amount || isNaN(amount)) {
    return res.status(400).json({ message: 'Missing or invalid parameters' });
  }
  try {
    await pool.query(
      `INSERT INTO user_balances (user_id, coin, balance)
       VALUES ($1, $2, $3)
       ON CONFLICT (user_id, coin)
       DO UPDATE SET balance = user_balances.balance + EXCLUDED.balance`,
      [user_id, coin, amount]
    );
    res.json({ message: `Added ${amount} ${coin} to user ${user_id}` });
  } catch (err) {
    res.status(500).json({ message: 'Failed to add balance', detail: err.message });
  }
});

// === Manual Balance Reduce ===
app.post('/api/admin/user/:id/reduce-balance', requireAdminAuth, async (req, res) => {
  const { id } = req.params;
  const { coin, amount } = req.body;
  if (!id || !coin || !amount || isNaN(amount)) {
    return res.status(400).json({ message: 'Missing or invalid parameters' });
  }
  try {
    const { rowCount } = await pool.query(
      `UPDATE user_balances
        SET balance = balance - $1
        WHERE user_id = $2 AND coin = $3 AND balance >= $1`,
      [amount, id, coin]
    );
    if (rowCount === 0) {
      return res.status(400).json({ message: "Insufficient balance or invalid user/coin" });
    }
    res.json({ message: `Reduced ${amount} ${coin} from user ${id}` });
  } catch (err) {
    res.status(500).json({ message: 'Failed to reduce balance', detail: err.message });
  }
});

// === Freeze Balance ===
app.post('/api/admin/freeze-balance', requireAdminAuth, async (req, res) => {
  const { user_id, coin, amount } = req.body;
  if (!user_id || !coin || !amount || isNaN(amount)) {
    return res.status(400).json({ message: 'Missing or invalid parameters' });
  }
  try {
    const { rowCount } = await pool.query(
      `UPDATE user_balances
       SET balance = balance - $1,
           frozen = COALESCE(frozen, 0) + $1
       WHERE user_id = $2 AND coin = $3 AND balance >= $1`,
      [amount, user_id, coin]
    );

    if (rowCount === 0) {
      return res.status(400).json({ message: "Insufficient balance or invalid user/coin" });
    }

    res.json({ message: `Froze ${amount} ${coin} for user ${user_id}` });
  } catch (err) {
    res.status(500).json({ message: 'Failed to freeze balance', detail: err.message });
  }
});


app.listen(PORT, () => {
  console.log(`NovaChain Admin Backend running on port ${PORT}`);
});
