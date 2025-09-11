// setupAdmin.js
require('dotenv').config();
const bcrypt = require('bcryptjs');
const pool = require('./db'); // Make sure this path is correct

async function createOrUpdateAdmin() {
  const email = process.env.ADMIN_EMAIL;
  const password = process.env.ADMIN_PASSWORD;
  const role = 'superadmin';

  if (!email || !password) {
      console.error('ADMIN_EMAIL and ADMIN_PASSWORD must be set in your .env file.');
      pool.end();
      return;
  }

  console.log(`Setting up admin user: ${email}`);

  const salt = await bcrypt.genSalt(10);
  const password_hash = await bcrypt.hash(password, salt);

  try {
    const existing = await pool.query('SELECT * FROM admins WHERE email = $1', [email]);
    if (existing.rows.length > 0) {
        console.log('Admin already exists. Updating password...');
        await pool.query('UPDATE admins SET password_hash = $1, role = $2 WHERE email = $3', [password_hash, role, email]);
        console.log('Admin password updated successfully.');
    } else {
        console.log('Creating new admin...');
        await pool.query(
          'INSERT INTO admins (email, password_hash, role) VALUES ($1, $2, $3)',
          [email, password_hash, role]
        );
        console.log('Admin user created successfully.');
    }
  } catch (error) {
    console.error('Error during admin setup:', error.message);
  } finally {
    pool.end();
  }
}

createOrUpdateAdmin();