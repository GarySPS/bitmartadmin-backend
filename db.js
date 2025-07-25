// db.js
const { Pool } = require('pg');
require('dotenv').config();

const pool = new Pool({
  connectionString: process.env.DATABASE_URL, // <--- change this line!
  ssl: { rejectUnauthorized: false }, // Required for Supabase
});

module.exports = pool;