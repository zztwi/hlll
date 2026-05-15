import 'dotenv/config'
import express from 'express'
import cors from 'cors'
import jwt from 'jsonwebtoken'
import bcrypt from 'bcryptjs'
import crypto from 'crypto'
import helmet from 'helmet'
import rateLimit from 'express-rate-limit'
import path from 'path'
import fs from 'fs'
import { fileURLToPath } from 'url'
import { query, initDb } from './src/db.js'
import { createPayPalOrder, capturePayPalOrder } from './src/paypal.js'
import { plans } from './src/plans.js'

const __filename = fileURLToPath(import.meta.url)
const __dirname = path.dirname(__filename)

const app = express()
const PORT = process.env.PORT || 3001
const JWT_SECRET = process.env.JWT_SECRET || 'change-this-secret'
const ADMIN_SECRET = process.env.ADMIN_SECRET || ''
const FRONTEND_URL = process.env.FRONTEND_URL || 'http://localhost:5173'
const CORS_ORIGINS = process.env.CORS_ORIGIN
  ? process.env.CORS_ORIGIN.split(',').map((item) => item.trim()).filter(Boolean)
  : true

app.set('trust proxy', 1)
app.use(helmet({ crossOriginResourcePolicy: false }))
app.use(cors({ origin: CORS_ORIGINS, credentials: true }))
app.use(express.json({ limit: '1mb' }))

const apiLimiter = rateLimit({
  windowMs: 60 * 1000,
  limit: 160,
  standardHeaders: true,
  legacyHeaders: false,
})

const authLimiter = rateLimit({
  windowMs: 10 * 60 * 1000,
  limit: 30,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'Too many attempts. Try again later.' },
})

app.use('/api', apiLimiter)

function asyncHandler(fn) {
  return (req, res, next) => Promise.resolve(fn(req, res, next)).catch(next)
}

function normalizeEmail(email) {
  return String(email || '').trim().toLowerCase()
}

function publicUser(user) {
  return { id: user.id, email: user.email, created_at: user.created_at }
}

function sign(user) {
  return jwt.sign({ id: user.id, email: user.email }, JWT_SECRET, { expiresIn: '30d' })
}

function auth(req, res, next) {
  try {
    const header = req.headers.authorization || ''
    const token = header.startsWith('Bearer ') ? header.slice(7) : req.query.token
    if (!token) return res.status(401).json({ error: 'Login required.' })
    req.user = jwt.verify(token, JWT_SECRET)
    next()
  } catch {
    res.status(401).json({ error: 'Invalid session.' })
  }
}

function adminAuth(req, res, next) {
  const provided = req.headers['x-admin-secret'] || req.query.adminSecret
  if (!ADMIN_SECRET) return res.status(500).json({ error: 'ADMIN_SECRET is not configured on the backend.' })
  if (!provided || provided !== ADMIN_SECRET) return res.status(401).json({ error: 'Invalid admin password.' })
  next()
}

function addDays(days) {
  if (!days) return null
  const date = new Date()
  date.setDate(date.getDate() + Number(days))
  return date.toISOString()
}

function generateLicenseKey(planId = 'MANUAL') {
  const clean = String(planId).toUpperCase().replace(/[^A-Z0-9]/g, '').slice(0, 10) || 'MANUAL'
  const chunks = Array.from({ length: 4 }, () => crypto.randomBytes(2).toString('hex').toUpperCase())
  return `EQY-${clean}-${chunks.join('-')}`
}

function isLicenseActive(license) {
  return Boolean(
    license &&
    license.status === 'active' &&
    (!license.expires_at || new Date(license.expires_at) > new Date())
  )
}

async function getActiveLicenses(userId) {
  const result = await query(
    `SELECT id, key, plan_id, status, expires_at, premium, hwid, last_verified_at, created_at
     FROM licenses
     WHERE user_id = $1
     ORDER BY created_at DESC`,
    [userId]
  )

  return result.rows.map((license) => ({
    ...license,
    is_active: isLicenseActive(license),
    expires_at: license.expires_at ? new Date(license.expires_at).toISOString() : null,
    created_at: license.created_at ? new Date(license.created_at).toISOString() : null,
    last_verified_at: license.last_verified_at ? new Date(license.last_verified_at).toISOString() : null,
  }))
}

async function getMyHwidRequests(userId) {
  const result = await query(
    `SELECT r.id, r.reason, r.status, r.admin_note, r.reviewed_at, r.created_at,
            l.key, l.plan_id
     FROM hwid_reset_requests r
     JOIN licenses l ON l.id = r.license_id
     WHERE r.user_id = $1
     ORDER BY r.created_at DESC
     LIMIT 20`,
    [userId]
  )
  return result.rows
}

async function requireActiveLicense(req, res, next) {
  try {
    const result = await query(
      `SELECT id FROM licenses
       WHERE user_id = $1
       AND status = 'active'
       AND (expires_at IS NULL OR expires_at > NOW())
       LIMIT 1`,
      [req.user.id]
    )

    if (!result.rows.length) return res.status(403).json({ error: 'Active license required.' })
    next()
  } catch (error) {
    next(error)
  }
}

app.get('/', (_, res) => {
  res.json({ ok: true, name: 'EQY Backend', status: 'online', frontend: FRONTEND_URL })
})

app.get('/api/health', (_, res) => res.json({ ok: true, status: 'online' }))

app.post('/api/auth/register', authLimiter, asyncHandler(async (req, res) => {
  const email = normalizeEmail(req.body.email)
  const password = String(req.body.password || '')

  if (!email.includes('@')) return res.status(400).json({ error: 'Valid email required.' })
  if (password.length < 6) return res.status(400).json({ error: 'Password must be at least 6 characters.' })

  const exists = await query('SELECT id FROM users WHERE email = $1', [email])
  if (exists.rows.length) return res.status(409).json({ error: 'Email already registered.' })

  const hash = await bcrypt.hash(password, 12)
  const created = await query(
    'INSERT INTO users(email, password_hash) VALUES($1, $2) RETURNING id, email, created_at',
    [email, hash]
  )

  const user = created.rows[0]
  res.json({ user: publicUser(user), token: sign(user) })
}))

app.post('/api/auth/login', authLimiter, asyncHandler(async (req, res) => {
  const email = normalizeEmail(req.body.email)
  const password = String(req.body.password || '')

  const found = await query('SELECT id, email, password_hash, created_at FROM users WHERE email = $1', [email])
  if (!found.rows.length) return res.status(401).json({ error: 'Invalid login.' })

  const user = found.rows[0]
  const ok = await bcrypt.compare(password, user.password_hash)
  if (!ok) return res.status(401).json({ error: 'Invalid login.' })

  res.json({ user: publicUser(user), token: sign(user) })
}))

app.get('/api/auth/me', auth, asyncHandler(async (req, res) => {
  const userRes = await query('SELECT id, email, created_at FROM users WHERE id = $1', [req.user.id])
  if (!userRes.rows.length) return res.status(404).json({ error: 'User not found.' })

  const licenses = await getActiveLicenses(req.user.id)
  const hwidRequests = await getMyHwidRequests(req.user.id)
  res.json({ user: publicUser(userRes.rows[0]), licenses, hwidRequests })
}))

app.post('/api/auth/change-password', auth, authLimiter, asyncHandler(async (req, res) => {
  const currentPassword = String(req.body.currentPassword || '')
  const newPassword = String(req.body.newPassword || '')

  if (!currentPassword || !newPassword) return res.status(400).json({ error: 'Current and new password are required.' })
  if (newPassword.length < 6) return res.status(400).json({ error: 'New password must be at least 6 characters.' })

  const found = await query('SELECT id, password_hash FROM users WHERE id = $1', [req.user.id])
  if (!found.rows.length) return res.status(404).json({ error: 'User not found.' })

  const ok = await bcrypt.compare(currentPassword, found.rows[0].password_hash)
  if (!ok) return res.status(401).json({ error: 'Current password is incorrect.' })

  const hash = await bcrypt.hash(newPassword, 12)
  await query('UPDATE users SET password_hash = $1 WHERE id = $2', [hash, req.user.id])
  res.json({ ok: true, message: 'Password updated successfully.' })
}))

app.post('/api/license/activate', auth, asyncHandler(async (req, res) => {
  const key = String(req.body.key || '').trim().toUpperCase()
  if (!key) return res.status(400).json({ error: 'License key required.' })

  const found = await query('SELECT * FROM licenses WHERE key = $1', [key])
  if (!found.rows.length) return res.status(404).json({ error: 'License not found.' })

  const license = found.rows[0]
  if (license.status !== 'active') return res.status(403).json({ error: 'License is not active.' })
  if (license.expires_at && new Date(license.expires_at) < new Date()) {
    await query('UPDATE licenses SET status = $1 WHERE id = $2', ['expired', license.id])
    return res.status(403).json({ error: 'License expired.' })
  }

  if (license.user_id && Number(license.user_id) !== Number(req.user.id)) {
    return res.status(409).json({ error: 'This license is already linked to another account.' })
  }

  await query('UPDATE licenses SET user_id = $1 WHERE id = $2', [req.user.id, license.id])
  res.json({ ok: true, message: 'License activated on your account.' })
}))

app.post('/api/license/hwid-reset-request', auth, asyncHandler(async (req, res) => {
  const key = String(req.body.key || '').trim().toUpperCase()
  const reason = String(req.body.reason || '').trim().slice(0, 600)

  if (!key) return res.status(400).json({ error: 'License key required.' })

  const licenseRes = await query('SELECT id, user_id FROM licenses WHERE key = $1 AND user_id = $2', [key, req.user.id])
  if (!licenseRes.rows.length) return res.status(404).json({ error: 'License not found on your account.' })

  const openRequest = await query(
    `SELECT id FROM hwid_reset_requests
     WHERE license_id = $1 AND status = 'pending'
     LIMIT 1`,
    [licenseRes.rows[0].id]
  )

  if (openRequest.rows.length) return res.status(409).json({ error: 'You already have a pending HWID reset request.' })

  await query(
    `INSERT INTO hwid_reset_requests(user_id, license_id, reason, status)
     VALUES($1, $2, $3, 'pending')`,
    [req.user.id, licenseRes.rows[0].id, reason || 'No reason provided.']
  )

  res.json({ ok: true, message: 'HWID reset request sent. Waiting for admin review.' })
}))

app.post('/api/paypal/create-order', auth, asyncHandler(async (req, res) => {
  const { planId } = req.body
  const plan = plans[planId]
  if (!plan) return res.status(400).json({ error: 'Unknown plan.' })

  const order = await createPayPalOrder({
    amount: plan.price.toFixed(2),
    currency: 'EUR',
    description: `EQY Tweak ${plan.name}`,
    returnUrl: `${FRONTEND_URL}?paypal=success`,
    cancelUrl: `${FRONTEND_URL}?paypal=cancel`,
  })

  await query(
    `INSERT INTO orders(paypal_order_id, user_id, plan_id, amount, status)
     VALUES($1, $2, $3, $4, $5)
     ON CONFLICT (paypal_order_id) DO NOTHING`,
    [order.id, req.user.id, planId, plan.price, 'created']
  )

  const approval = order.links?.find((l) => l.rel === 'approve')
  if (!approval?.href) return res.status(502).json({ error: 'PayPal approval URL missing.' })
  res.json({ orderId: order.id, approvalUrl: approval.href })
}))

app.post('/api/paypal/capture-order', auth, asyncHandler(async (req, res) => {
  const { orderId } = req.body
  if (!orderId) return res.status(400).json({ error: 'Order id required.' })

  const orderRes = await query('SELECT * FROM orders WHERE paypal_order_id = $1 AND user_id = $2', [orderId, req.user.id])
  if (!orderRes.rows.length) return res.status(404).json({ error: 'Order not found.' })

  const orderRecord = orderRes.rows[0]
  const existingLicense = await query('SELECT * FROM licenses WHERE order_id = $1', [orderRecord.id])
  if (existingLicense.rows.length) return res.json({ license: existingLicense.rows[0] })

  const capture = await capturePayPalOrder(orderId)
  if (capture.status !== 'COMPLETED') return res.status(400).json({ error: 'Payment not completed.' })

  const plan = plans[orderRecord.plan_id]
  if (!plan) return res.status(400).json({ error: 'Plan no longer exists.' })

  const key = generateLicenseKey(orderRecord.plan_id)
  const expiresAt = addDays(plan.days)

  await query('UPDATE orders SET status = $1, paid_at = NOW() WHERE id = $2', ['paid', orderRecord.id])

  const created = await query(
    `INSERT INTO licenses(user_id, order_id, key, plan_id, status, expires_at, premium)
     VALUES($1,$2,$3,$4,$5,$6,$7)
     RETURNING *`,
    [req.user.id, orderRecord.id, key, orderRecord.plan_id, 'active', expiresAt, plan.premium]
  )

  res.json({ license: created.rows[0] })
}))

app.post('/api/license/verify', asyncHandler(async (req, res) => {
  const key = String(req.body.key || '').trim().toUpperCase()
  const hwid = String(req.body.hwid || '').trim()
  const appVersion = String(req.body.appVersion || '').trim()

  if (!key) return res.status(400).json({ ok: false, error: 'License key required.' })

  const lic = await query('SELECT * FROM licenses WHERE key = $1', [key])
  if (!lic.rows.length) return res.status(404).json({ ok: false, error: 'License not found.' })

  const license = lic.rows[0]

  if (license.status !== 'active') return res.status(403).json({ ok: false, error: 'License inactive.' })

  if (license.expires_at && new Date(license.expires_at) < new Date()) {
    await query('UPDATE licenses SET status = $1 WHERE id = $2', ['expired', license.id])
    return res.status(403).json({ ok: false, error: 'License expired.' })
  }

  if (!license.hwid && hwid) {
    await query('UPDATE licenses SET hwid = $1, last_verified_at = NOW(), last_app_version = $2 WHERE id = $3', [hwid, appVersion, license.id])
    license.hwid = hwid
  }

  if (license.hwid && hwid && license.hwid !== hwid) {
    return res.status(403).json({ ok: false, error: 'License already used on another PC.' })
  }

  await query('UPDATE licenses SET last_verified_at = NOW(), last_app_version = $1 WHERE id = $2', [appVersion, license.id])

  res.json({
    ok: true,
    status: license.status,
    plan: license.plan_id,
    premium: license.premium,
    expires_at: license.expires_at,
    server_time: new Date().toISOString(),
  })
}))

app.get('/api/download/:kind', auth, requireActiveLicense, (req, res) => {
  const file = req.params.kind === 'msi' ? 'eqy-tweak-installer.msi' : 'eqy-tweak-setup.exe'
  const fullPath = path.join(__dirname, 'downloads', file)

  if (!fs.existsSync(fullPath)) return res.status(404).json({ error: 'Installer not uploaded yet.' })
  res.download(fullPath)
})

app.get('/latest.json', (_, res) => {
  const fullPath = path.join(__dirname, 'downloads', 'latest.json')
  if (!fs.existsSync(fullPath)) return res.status(404).json({ error: 'latest.json not uploaded yet.' })
  res.sendFile(fullPath)
})

/* Admin panel API */
app.get('/api/admin/overview', adminAuth, asyncHandler(async (_, res) => {
  const [users, licenses, pending, paid] = await Promise.all([
    query('SELECT COUNT(*)::int AS count FROM users'),
    query('SELECT COUNT(*)::int AS count FROM licenses'),
    query("SELECT COUNT(*)::int AS count FROM hwid_reset_requests WHERE status = 'pending'"),
    query("SELECT COALESCE(SUM(amount), 0)::float AS total FROM orders WHERE status = 'paid'"),
  ])

  res.json({
    users: users.rows[0].count,
    licenses: licenses.rows[0].count,
    pendingHwidRequests: pending.rows[0].count,
    paidRevenue: paid.rows[0].total,
  })
}))

app.get('/api/admin/users', adminAuth, asyncHandler(async (_, res) => {
  const result = await query(
    `SELECT u.id, u.email, u.created_at,
            COUNT(l.id)::int AS licenses_count,
            COUNT(l.id) FILTER (WHERE l.status = 'active')::int AS active_licenses
     FROM users u
     LEFT JOIN licenses l ON l.user_id = u.id
     GROUP BY u.id
     ORDER BY u.created_at DESC
     LIMIT 300`
  )
  res.json({ users: result.rows })
}))

app.get('/api/admin/licenses', adminAuth, asyncHandler(async (_, res) => {
  const result = await query(
    `SELECT l.id, l.key, l.plan_id, l.status, l.hwid, l.premium, l.expires_at, l.created_at, l.last_verified_at,
            u.email
     FROM licenses l
     LEFT JOIN users u ON u.id = l.user_id
     ORDER BY l.created_at DESC
     LIMIT 500`
  )
  res.json({ licenses: result.rows })
}))

app.post('/api/admin/licenses', adminAuth, asyncHandler(async (req, res) => {
  const email = normalizeEmail(req.body.email)
  const planId = String(req.body.planId || 'manual_lifetime').trim()
  const status = String(req.body.status || 'active').trim()
  const days = req.body.days === null || req.body.days === '' || req.body.days === undefined ? null : Number(req.body.days)
  const premium = Boolean(req.body.premium)

  if (!email.includes('@')) return res.status(400).json({ error: 'Valid user email required.' })

  const userRes = await query('SELECT id, email FROM users WHERE email = $1', [email])
  if (!userRes.rows.length) return res.status(404).json({ error: 'User not found. Ask them to register first.' })

  const key = generateLicenseKey(planId)
  const expiresAt = addDays(days)

  const created = await query(
    `INSERT INTO licenses(user_id, key, plan_id, status, expires_at, premium)
     VALUES($1,$2,$3,$4,$5,$6)
     RETURNING *`,
    [userRes.rows[0].id, key, planId, status, expiresAt, premium]
  )

  res.json({ license: created.rows[0] })
}))

app.patch('/api/admin/licenses/:id/revoke', adminAuth, asyncHandler(async (req, res) => {
  const updated = await query('UPDATE licenses SET status = $1 WHERE id = $2 RETURNING *', ['revoked', req.params.id])
  if (!updated.rows.length) return res.status(404).json({ error: 'License not found.' })
  res.json({ license: updated.rows[0] })
}))

app.patch('/api/admin/licenses/:id/reset-hwid', adminAuth, asyncHandler(async (req, res) => {
  const updated = await query('UPDATE licenses SET hwid = NULL WHERE id = $1 RETURNING *', [req.params.id])
  if (!updated.rows.length) return res.status(404).json({ error: 'License not found.' })
  res.json({ license: updated.rows[0] })
}))

app.get('/api/admin/hwid-requests', adminAuth, asyncHandler(async (_, res) => {
  const result = await query(
    `SELECT r.id, r.reason, r.status, r.admin_note, r.created_at, r.reviewed_at,
            u.email, l.id AS license_id, l.key, l.plan_id, l.hwid
     FROM hwid_reset_requests r
     JOIN users u ON u.id = r.user_id
     JOIN licenses l ON l.id = r.license_id
     ORDER BY
       CASE WHEN r.status = 'pending' THEN 0 ELSE 1 END,
       r.created_at DESC
     LIMIT 500`
  )
  res.json({ requests: result.rows })
}))

app.post('/api/admin/hwid-requests/:id/approve', adminAuth, asyncHandler(async (req, res) => {
  const note = String(req.body.note || 'Approved by admin.').slice(0, 500)
  const requestRes = await query('SELECT * FROM hwid_reset_requests WHERE id = $1', [req.params.id])
  if (!requestRes.rows.length) return res.status(404).json({ error: 'Request not found.' })

  const request = requestRes.rows[0]
  await query('UPDATE licenses SET hwid = NULL WHERE id = $1', [request.license_id])
  const updated = await query(
    `UPDATE hwid_reset_requests
     SET status = 'approved', admin_note = $1, reviewed_at = NOW()
     WHERE id = $2
     RETURNING *`,
    [note, req.params.id]
  )

  res.json({ request: updated.rows[0], message: 'HWID reset approved and license HWID cleared.' })
}))

app.post('/api/admin/hwid-requests/:id/decline', adminAuth, asyncHandler(async (req, res) => {
  const note = String(req.body.note || 'Declined by admin.').slice(0, 500)
  const updated = await query(
    `UPDATE hwid_reset_requests
     SET status = 'declined', admin_note = $1, reviewed_at = NOW()
     WHERE id = $2
     RETURNING *`,
    [note, req.params.id]
  )
  if (!updated.rows.length) return res.status(404).json({ error: 'Request not found.' })
  res.json({ request: updated.rows[0] })
}))

app.use((req, res) => {
  res.status(404).json({ error: 'Route not found.' })
})

app.use((err, req, res, next) => {
  console.error(err)
  res.status(500).json({ error: err.message || 'Internal server error.' })
})

await initDb()
app.listen(PORT, () => console.log(`EQY backend running on ${PORT}`))
