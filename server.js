import 'dotenv/config'
import express from 'express'
import cors from 'cors'
import jwt from 'jsonwebtoken'
import bcrypt from 'bcryptjs'
import crypto from 'crypto'
import path from 'path'
import { fileURLToPath } from 'url'
import { query, initDb } from './src/db.js'
import { createPayPalOrder, capturePayPalOrder } from './src/paypal.js'
import { plans } from './src/plans.js'

const __filename = fileURLToPath(import.meta.url)
const __dirname = path.dirname(__filename)

const app = express()
const PORT = process.env.PORT || 3001
const JWT_SECRET = process.env.JWT_SECRET || 'change-this-secret'
const FRONTEND_URL = process.env.FRONTEND_URL || 'http://localhost:5173'

app.use(cors({ origin: process.env.CORS_ORIGIN?.split(',') || true }))
app.use(express.json())

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
  const clean = planId.toUpperCase().replace(/[^A-Z0-9]/g, '').slice(0, 8)
  const a = crypto.randomBytes(2).toString('hex').toUpperCase()
  const b = crypto.randomBytes(2).toString('hex').toUpperCase()
  const c = crypto.randomBytes(2).toString('hex').toUpperCase()
  return `EQY-${clean}-${a}-${b}-${c}`
}

app.get('/api/health', (_, res) => res.json({ ok: true }))

app.post('/api/auth/register', async (req, res) => {
  const { email, password } = req.body
  if (!email || !password || password.length < 6) return res.status(400).json({ error: 'Email and password min 6 chars required.' })

  const exists = await query('SELECT id FROM users WHERE email = $1', [email.toLowerCase()])
  if (exists.rows.length) return res.status(409).json({ error: 'Email already registered.' })

  const hash = await bcrypt.hash(password, 10)
  const created = await query('INSERT INTO users(email, password_hash) VALUES($1, $2) RETURNING id, email', [email.toLowerCase(), hash])
  const user = created.rows[0]
  res.json({ user, token: sign(user) })
})

app.post('/api/auth/login', async (req, res) => {
  const { email, password } = req.body
  const found = await query('SELECT id, email, password_hash FROM users WHERE email = $1', [email.toLowerCase()])
  if (!found.rows.length) return res.status(401).json({ error: 'Invalid login.' })

  const user = found.rows[0]
  const ok = await bcrypt.compare(password, user.password_hash)
  if (!ok) return res.status(401).json({ error: 'Invalid login.' })

  res.json({ user: { id: user.id, email: user.email }, token: sign(user) })
})

app.get('/api/auth/me', auth, async (req, res) => {
  const userRes = await query('SELECT id, email FROM users WHERE id = $1', [req.user.id])
  if (!userRes.rows.length) return res.status(404).json({ error: 'User not found.' })

  const licenses = await query('SELECT key, plan_id, status, expires_at, premium FROM licenses WHERE user_id = $1 ORDER BY created_at DESC', [req.user.id])
  res.json({ user: userRes.rows[0], licenses: licenses.rows })
})

app.post('/api/paypal/create-order', auth, async (req, res) => {
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
    'INSERT INTO orders(paypal_order_id, user_id, plan_id, amount, status) VALUES($1, $2, $3, $4, $5)',
    [order.id, req.user.id, planId, plan.price, 'created']
  )

  const approval = order.links.find((l) => l.rel === 'approve')
  res.json({ orderId: order.id, approvalUrl: approval?.href })
})

app.post('/api/paypal/capture-order', auth, async (req, res) => {
  const { orderId } = req.body
  const orderRes = await query('SELECT * FROM orders WHERE paypal_order_id = $1 AND user_id = $2', [orderId, req.user.id])
  if (!orderRes.rows.length) return res.status(404).json({ error: 'Order not found.' })

  const existingLicense = await query('SELECT * FROM licenses WHERE order_id = $1', [orderRes.rows[0].id])
  if (existingLicense.rows.length) return res.json({ license: existingLicense.rows[0] })

  const capture = await capturePayPalOrder(orderId)
  if (capture.status !== 'COMPLETED') return res.status(400).json({ error: 'Payment not completed.' })

  const plan = plans[orderRes.rows[0].plan_id]
  const key = generateLicenseKey(orderRes.rows[0].plan_id)
  const expiresAt = addDays(plan.days)

  await query('UPDATE orders SET status = $1 WHERE id = $2', ['paid', orderRes.rows[0].id])

  const created = await query(
    'INSERT INTO licenses(user_id, order_id, key, plan_id, status, expires_at, premium) VALUES($1,$2,$3,$4,$5,$6,$7) RETURNING *',
    [req.user.id, orderRes.rows[0].id, key, orderRes.rows[0].plan_id, 'active', expiresAt, plan.premium]
  )

  res.json({ license: created.rows[0] })
})

app.post('/api/license/verify', async (req, res) => {
  const { key, hwid } = req.body
  const lic = await query('SELECT * FROM licenses WHERE key = $1', [key])
  if (!lic.rows.length) return res.status(404).json({ ok: false, error: 'License not found.' })

  const license = lic.rows[0]
  if (license.status !== 'active') return res.status(403).json({ ok: false, error: 'License inactive.' })
  if (license.expires_at && new Date(license.expires_at) < new Date()) return res.status(403).json({ ok: false, error: 'License expired.' })

  if (!license.hwid && hwid) {
    await query('UPDATE licenses SET hwid = $1 WHERE id = $2', [hwid, license.id])
    license.hwid = hwid
  }

  if (license.hwid && hwid && license.hwid !== hwid) return res.status(403).json({ ok: false, error: 'License already used on another PC.' })

  res.json({
    ok: true,
    status: license.status,
    plan: license.plan_id,
    premium: license.premium,
    expires_at: license.expires_at,
  })
})

app.get('/api/download/:kind', auth, (req, res) => {
  const file = req.params.kind === 'msi' ? 'eqy-tweak-installer.msi' : 'eqy-tweak-setup.exe'
  res.download(path.join(__dirname, 'downloads', file))
})

app.get('/latest.json', (_, res) => {
  res.sendFile(path.join(__dirname, 'downloads', 'latest.json'))
})

await initDb()
app.listen(PORT, () => console.log(`EQY backend running on ${PORT}`))
