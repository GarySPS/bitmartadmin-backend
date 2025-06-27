// test-db.js
const { Pool } = require('pg');
require('dotenv').config();

const pool = new Pool({
  connectionString: process.env.DATABASE_URL, // Uses your .env DB URL
});

pool.query('SELECT * FROM users LIMIT 1', (err, res) => {
  if (err) { 
    console.error("❌ DB ERROR:", err); 
    process.exit(1); 
  }
  console.log("✅ USERS ROW:", res.rows[0]);
  process.exit(0);
});
