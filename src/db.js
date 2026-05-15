import pg from 'pg'

const { Pool } = pg

if (!process.env.DATABASE_URL) {
  console.warn('DATABASE_URL is missing. PostgreSQL connection will fail until it is configured.')
}

export const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.DATABASE_SSL === 'false' ? false : { rejectUnauthorized: false },
})

export function query(text, params) {
  return pool.query(text, params)
}

export async function initDb() {
  await query(`
    CREATE TABLE IF NOT EXISTS users (
      id SERIAL PRIMARY KEY,
      email TEXT UNIQUE NOT NULL,
      password_hash TEXT NOT NULL,
      created_at TIMESTAMPTZ DEFAULT NOW()
    );

    CREATE TABLE IF NOT EXISTS orders (
      id SERIAL PRIMARY KEY,
      paypal_order_id TEXT UNIQUE NOT NULL,
      user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
      plan_id TEXT NOT NULL,
      amount NUMERIC NOT NULL,
      status TEXT NOT NULL DEFAULT 'created',
      created_at TIMESTAMPTZ DEFAULT NOW()
    );

    CREATE TABLE IF NOT EXISTS licenses (
      id SERIAL PRIMARY KEY,
      user_id INTEGER REFERENCES users(id) ON DELETE SET NULL,
      order_id INTEGER REFERENCES orders(id) ON DELETE SET NULL,
      key TEXT UNIQUE NOT NULL,
      plan_id TEXT NOT NULL,
      status TEXT NOT NULL DEFAULT 'active',
      hwid TEXT,
      expires_at TIMESTAMPTZ,
      premium BOOLEAN DEFAULT FALSE,
      created_at TIMESTAMPTZ DEFAULT NOW()
    );

    CREATE TABLE IF NOT EXISTS hwid_reset_requests (
      id SERIAL PRIMARY KEY,
      user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
      license_id INTEGER REFERENCES licenses(id) ON DELETE CASCADE,
      reason TEXT,
      status TEXT NOT NULL DEFAULT 'pending',
      admin_note TEXT,
      reviewed_at TIMESTAMPTZ,
      created_at TIMESTAMPTZ DEFAULT NOW()
    );
  `)

  await query(`
    ALTER TABLE orders ADD COLUMN IF NOT EXISTS paid_at TIMESTAMPTZ;
    ALTER TABLE licenses ADD COLUMN IF NOT EXISTS last_verified_at TIMESTAMPTZ;
    ALTER TABLE licenses ADD COLUMN IF NOT EXISTS last_app_version TEXT;
    ALTER TABLE hwid_reset_requests ADD COLUMN IF NOT EXISTS admin_note TEXT;
    ALTER TABLE hwid_reset_requests ADD COLUMN IF NOT EXISTS reviewed_at TIMESTAMPTZ;
  `)
}
