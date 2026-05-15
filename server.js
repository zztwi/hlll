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
import { plans, publicPlans } from './src/plans.js'

const __filename = fileURLToPath(import.meta.url)
const __dirname = path.dirname(__filename)

const app = express()
const PORT = process.env.PORT || 3001
const JWT_SECRET = process.env.JWT_SECRET || 'change-this-secret'
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
  limit: 120,
  standardHeaders: true,
  legacyHeaders: false,
})

const authLimiter = rateLimit({
  windowMs: 10 * 60 * 1000,
  limit: 25,
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

function addDays(days) {
  if (!days) return null
  const date = new Date()
  date.setDate(date.getDate() + days)
  return date.toISOString()
}

function generateLicenseKey(planId) {
  const clean = String(planId).toUpperCase().replace(/[^A-Z0-9]/g, '').slice(0, 10)
  const chunks = Array.from({ length: 4 }, () => crypto.randomBytes(2).toString('hex').toUpperCase())
  return `EQY-${clean}-${chunks.join('-')}`
}

function isLicenseActive(license) {
  if (!license) return false
  if (license.status !== 'active') return false
  if (license.expires_at && new Date(license.expires_at) < new Date()) return false
  return true
}

async function getActiveLicenses(userId) {
  const result = await query(
    `SELECT key, plan_id, status, expires_at, premium, hwid, last_verified_at, created_at
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

    if (!result.rows.length) {
      return res.status(403).json({ error: 'Active license required.' })
    }

    next()
  } catch (error) {
    next(error)
  }
}

app.get('/', (_, res) => {
  res.json({
    ok: true,
    name: 'EQY Backend',
    status: 'online',
    frontend: FRONTEND_URL,
  })
})

app.get('/api/health', (_, res) => res.json({ ok: true, status: 'online' }))

app.get('/api/plans', (_, res) => {
  res.json({ plans: publicPlans })
})

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
  res.json({ user: publicUser(userRes.rows[0]), licenses })
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

  const approval = order.links?.find((link) => link.rel === 'approve')
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

app.post('/api/license/hwid-reset-request', auth, asyncHandler(async (req, res) => {
  const key = String(req.body.key || '').trim().toUpperCase()
  const reason = String(req.body.reason || '').trim().slice(0, 500)

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

  res.json({ ok: true, message: 'HWID reset request sent.' })
}))

app.get('/api/download/:kind', auth, requireActiveLicense, (req, res) => {
  const file = req.params.kind === 'msi' ? 'eqy-tweak-installer.msi' : 'eqy-tweak-setup.exe'
  const fullPath = path.join(__dirname, 'downloads', file)

  if (!fs.existsSync(fullPath)) {
    return res.status(404).json({ error: 'Installer not uploaded yet.' })
  }

  res.download(fullPath)
})

app.get('/latest.json', (_, res) => {
  const fullPath = path.join(__dirname, 'downloads', 'latest.json')
  if (!fs.existsSync(fullPath)) return res.status(404).json({ error: 'latest.json not uploaded yet.' })
  res.sendFile(fullPath)
})

app.use((req, res) => {
  res.status(404).json({ error: 'Route not found.' })
})

app.use((err, req, res, next) => {
  console.error(err)
  res.status(500).json({ error: err.message || 'Internal server error.' })
})

await initDb()
app.listen(PORT, () => console.log(`EQY backend running on ${PORT}`))
