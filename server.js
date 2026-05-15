import 'dotenv/config'
import express from 'express'
import cors from 'cors'
import jwt from 'jsonwebtoken'
import bcrypt from 'bcryptjs'
import crypto from 'crypto'
import path from 'path'
import { fileURLToPath } from 'url'
import rateLimit from 'express-rate-limit'
import { Resend } from 'resend'
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
const EMAIL_FROM = process.env.EMAIL_FROM || 'onboarding@resend.dev'
const EMAIL_ADMIN = process.env.EMAIL_ADMIN || ''
const resend = process.env.RESEND_API_KEY ? new Resend(process.env.RESEND_API_KEY) : null

app.use(cors({ origin: process.env.CORS_ORIGIN?.split(',') || true }))
app.use(express.json({ limit: '1mb' }))

const authLimiter = rateLimit({ windowMs: 15 * 60 * 1000, max: 80, standardHeaders: true, legacyHeaders: false })
const asyncHandler = (fn) => (req, res, next) => Promise.resolve(fn(req, res, next)).catch(next)

function sign(user) {
  return jwt.sign({ id: user.id, email: user.email }, JWT_SECRET, { expiresIn: '30d' })
}

function signAdmin() {
  return jwt.sign({ admin: true }, JWT_SECRET, { expiresIn: '12h' })
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
  try {
    const header = req.headers.authorization || ''
    const token = header.startsWith('Bearer ') ? header.slice(7) : ''
    if (!token) return res.status(401).json({ error: 'Admin login required.' })
    const payload = jwt.verify(token, JWT_SECRET)
    if (!payload?.admin) return res.status(403).json({ error: 'Admin access denied.' })
    next()
  } catch {
    res.status(401).json({ error: 'Invalid admin session.' })
  }
}

function addDays(days) {
  if (!days) return null
  const date = new Date()
  date.setDate(date.getDate() + Number(days))
  return date.toISOString()
}

function formatDate(value) {
  if (!value) return 'Lifetime'
  return new Date(value).toLocaleString('en-US', { dateStyle: 'medium', timeStyle: 'short' })
}

function generateLicenseKey(planId = 'manual') {
  const clean = String(planId).toUpperCase().replace(/[^A-Z0-9]/g, '').slice(0, 8) || 'MANUAL'
  const a = crypto.randomBytes(2).toString('hex').toUpperCase()
  const b = crypto.randomBytes(2).toString('hex').toUpperCase()
  const c = crypto.randomBytes(2).toString('hex').toUpperCase()
  return `EQY-${clean}-${a}-${b}-${c}`
}

async function userHasActiveLicense(userId) {
  const found = await query(
    `SELECT id FROM licenses
     WHERE user_id = $1
       AND status = 'active'
       AND (expires_at IS NULL OR expires_at > NOW())
     LIMIT 1`,
    [userId]
  )
  return found.rows.length > 0
}

function emailShell(title, content) {
  return `<div style="margin:0;padding:0;background:#02040a;font-family:Inter,Arial,sans-serif;color:#eaf4ff;"><div style="max-width:620px;margin:0 auto;padding:34px 18px;"><div style="border:1px solid rgba(56,189,248,.28);background:linear-gradient(180deg,#07142e,#030712);border-radius:22px;overflow:hidden;box-shadow:0 30px 90px rgba(10,115,255,.20);"><div style="padding:28px;border-bottom:1px solid rgba(255,255,255,.08);"><div style="font-size:12px;letter-spacing:.22em;color:#38bdf8;font-weight:800;">EQY TWEAK</div><h1 style="margin:10px 0 0;font-size:30px;line-height:1.05;color:#fff;">${title}</h1></div><div style="padding:28px;color:#b8c7dd;font-size:15px;line-height:1.75;">${content}</div><div style="padding:18px 28px;border-top:1px solid rgba(255,255,255,.08);color:#6f83a3;font-size:12px;">EQY Tweak • Premium Windows optimization</div></div></div></div>`
}

async function sendEmail({ to, subject, html }) {
  if (!resend || !to) {
    console.log('[email skipped]', subject, to || 'no-recipient')
    return
  }
  try {
    await resend.emails.send({ from: EMAIL_FROM, to, subject, html })
  } catch (error) {
    console.error('[email failed]', subject, error?.message || error)
  }
}

function licenseEmailHtml({ title = 'Your EQY license is ready', key, planId, premium, expiresAt }) {
  return emailShell(title, `<p>Your license has been generated successfully.</p><div style="margin:22px 0;padding:18px;border-radius:16px;border:1px solid rgba(56,189,248,.28);background:rgba(10,115,255,.10);"><div style="font-size:11px;letter-spacing:.16em;color:#38bdf8;font-weight:800;">LICENSE KEY</div><div style="margin-top:8px;font-family:Consolas,monospace;font-size:22px;color:#fff;font-weight:800;word-break:break-all;">${key}</div></div><p><strong style="color:#fff;">Plan:</strong> ${planId}</p><p><strong style="color:#fff;">Type:</strong> ${premium ? 'Premium' : 'Standard'}</p><p><strong style="color:#fff;">Expires:</strong> ${formatDate(expiresAt)}</p><p>You can activate it from your EQY account dashboard.</p><p><a href="${FRONTEND_URL}" style="display:inline-block;margin-top:12px;padding:13px 18px;border-radius:12px;background:#0a73ff;color:#fff;text-decoration:none;font-weight:800;">Open dashboard</a></p>`)
}

app.get('/api/health', (_, res) => res.json({ ok: true }))

app.post('/api/auth/register', authLimiter, asyncHandler(async (req, res) => {
  const email = String(req.body.email || '').toLowerCase().trim()
  const password = String(req.body.password || '')
  if (!email || !password || password.length < 6) return res.status(400).json({ error: 'Email and password min 6 chars required.' })
  const exists = await query('SELECT id FROM users WHERE email = $1', [email])
  if (exists.rows.length) return res.status(409).json({ error: 'Email already registered.' })
  const hash = await bcrypt.hash(password, 12)
  const created = await query('INSERT INTO users(email, password_hash) VALUES($1, $2) RETURNING id, email, created_at', [email, hash])
  const user = created.rows[0]
  await sendEmail({ to: user.email, subject: 'Welcome to EQY Tweak', html: emailShell('Welcome to EQY Tweak', `<p>Your EQY account has been created successfully.</p><p>You can now log in, manage licenses, request HWID resets, and download protected releases after activating a license.</p><p><a href="${FRONTEND_URL}" style="display:inline-block;margin-top:12px;padding:13px 18px;border-radius:12px;background:#0a73ff;color:#fff;text-decoration:none;font-weight:800;">Open EQY</a></p>`) })
  res.json({ user, token: sign(user) })
}))

app.post('/api/auth/login', authLimiter, asyncHandler(async (req, res) => {
  const email = String(req.body.email || '').toLowerCase().trim()
  const password = String(req.body.password || '')
  const found = await query('SELECT id, email, password_hash FROM users WHERE email = $1', [email])
  if (!found.rows.length) return res.status(401).json({ error: 'Invalid login.' })
  const user = found.rows[0]
  const ok = await bcrypt.compare(password, user.password_hash)
  if (!ok) return res.status(401).json({ error: 'Invalid login.' })
  res.json({ user: { id: user.id, email: user.email }, token: sign(user) })
}))

app.get('/api/auth/me', auth, asyncHandler(async (req, res) => {
  const userRes = await query('SELECT id, email, created_at FROM users WHERE id = $1', [req.user.id])
  if (!userRes.rows.length) return res.status(404).json({ error: 'User not found.' })
  const licenses = await query(`SELECT id, key, plan_id, status, expires_at, premium, hwid, created_at, last_verified_at, (status = 'active' AND (expires_at IS NULL OR expires_at > NOW())) AS is_active FROM licenses WHERE user_id = $1 ORDER BY created_at DESC`, [req.user.id])
  const hwidRequests = await query(`SELECT r.id, r.license_id, r.reason, r.status, r.created_at, r.reviewed_at, l.key AS license_key, l.plan_id FROM hwid_reset_requests r LEFT JOIN licenses l ON l.id = r.license_id WHERE r.user_id = $1 ORDER BY r.created_at DESC LIMIT 10`, [req.user.id])
  res.json({ user: userRes.rows[0], licenses: licenses.rows, hwidRequests: hwidRequests.rows })
}))

app.post('/api/auth/change-password', auth, authLimiter, asyncHandler(async (req, res) => {
  const currentPassword = String(req.body.currentPassword || '')
  const newPassword = String(req.body.newPassword || '')
  if (!currentPassword || !newPassword) return res.status(400).json({ error: 'Current and new password are required.' })
  if (newPassword.length < 6) return res.status(400).json({ error: 'New password must be at least 6 characters.' })
  const found = await query('SELECT id, email, password_hash FROM users WHERE id = $1', [req.user.id])
  if (!found.rows.length) return res.status(404).json({ error: 'User not found.' })
  const ok = await bcrypt.compare(currentPassword, found.rows[0].password_hash)
  if (!ok) return res.status(401).json({ error: 'Current password is incorrect.' })
  const hash = await bcrypt.hash(newPassword, 12)
  await query('UPDATE users SET password_hash = $1 WHERE id = $2', [hash, req.user.id])
  await sendEmail({ to: found.rows[0].email, subject: 'Your EQY password was changed', html: emailShell('Password changed', '<p>Your EQY account password was changed successfully.</p><p>If this was not you, contact support immediately.</p>') })
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
  if (license.user_id && Number(license.user_id) !== Number(req.user.id)) return res.status(409).json({ error: 'This license is already linked to another account.' })
  await query('UPDATE licenses SET user_id = $1 WHERE id = $2', [req.user.id, license.id])
  await sendEmail({ to: req.user.email, subject: 'EQY license activated', html: licenseEmailHtml({ title: 'License activated', key: license.key, planId: license.plan_id, premium: license.premium, expiresAt: license.expires_at }) })
  res.json({ ok: true, message: 'License activated on your account.' })
}))

app.post('/api/license/hwid-reset-request', auth, asyncHandler(async (req, res) => {
  const key = String(req.body.key || '').trim().toUpperCase()
  const reason = String(req.body.reason || '').trim().slice(0, 800)
  if (!key) return res.status(400).json({ error: 'License key required.' })
  const lic = await query('SELECT * FROM licenses WHERE key = $1 AND user_id = $2', [key, req.user.id])
  if (!lic.rows.length) return res.status(404).json({ error: 'License not found on your account.' })
  const license = lic.rows[0]
  const pending = await query('SELECT id FROM hwid_reset_requests WHERE license_id = $1 AND status = $2 LIMIT 1', [license.id, 'pending'])
  if (pending.rows.length) return res.status(409).json({ error: 'You already have a pending HWID reset request.' })
  const created = await query('INSERT INTO hwid_reset_requests(user_id, license_id, reason, status) VALUES($1, $2, $3, $4) RETURNING *', [req.user.id, license.id, reason || 'Requested from account dashboard.', 'pending'])
  await sendEmail({ to: req.user.email, subject: 'HWID reset request received', html: emailShell('HWID reset request received', `<p>Your HWID reset request for license <strong style="color:#fff;">${license.key}</strong> has been submitted and is pending review.</p>`) })
  if (EMAIL_ADMIN) await sendEmail({ to: EMAIL_ADMIN, subject: 'New EQY HWID reset request', html: emailShell('New HWID reset request', `<p><strong style="color:#fff;">User:</strong> ${req.user.email}</p><p><strong style="color:#fff;">License:</strong> ${license.key}</p><p><strong style="color:#fff;">Reason:</strong> ${reason || 'No reason provided.'}</p>`) })
  res.json({ ok: true, request: created.rows[0], message: 'HWID reset request submitted.' })
}))

app.post('/api/paypal/create-order', auth, asyncHandler(async (req, res) => {
  const { planId } = req.body
  const plan = plans[planId]
  if (!plan) return res.status(400).json({ error: 'Unknown plan.' })
  const order = await createPayPalOrder({ amount: plan.price.toFixed(2), currency: 'EUR', description: `EQY Tweak ${plan.name}`, returnUrl: `${FRONTEND_URL}?paypal=success`, cancelUrl: `${FRONTEND_URL}?paypal=cancel` })
  await query('INSERT INTO orders(paypal_order_id, user_id, plan_id, amount, status) VALUES($1, $2, $3, $4, $5) ON CONFLICT (paypal_order_id) DO NOTHING', [order.id, req.user.id, planId, plan.price, 'created'])
  const approval = order.links?.find((l) => l.rel === 'approve')
  if (!approval?.href) return res.status(500).json({ error: 'PayPal approval URL missing.' })
  res.json({ orderId: order.id, approvalUrl: approval.href })
}))

app.post('/api/paypal/capture-order', auth, asyncHandler(async (req, res) => {
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
  await query('UPDATE orders SET status = $1, paid_at = NOW() WHERE id = $2', ['paid', orderRes.rows[0].id])
  const created = await query('INSERT INTO licenses(user_id, order_id, key, plan_id, status, expires_at, premium) VALUES($1,$2,$3,$4,$5,$6,$7) RETURNING *', [req.user.id, orderRes.rows[0].id, key, orderRes.rows[0].plan_id, 'active', expiresAt, plan.premium])
  await sendEmail({ to: req.user.email, subject: 'Your EQY license key', html: licenseEmailHtml({ key, planId: orderRes.rows[0].plan_id, premium: plan.premium, expiresAt }) })
  res.json({ license: created.rows[0] })
}))

app.post('/api/license/verify', asyncHandler(async (req, res) => {
  const { key, hwid, appVersion } = req.body
  const lic = await query('SELECT * FROM licenses WHERE key = $1', [String(key || '').trim().toUpperCase()])
  if (!lic.rows.length) return res.status(404).json({ ok: false, error: 'License not found.' })
  const license = lic.rows[0]
  if (license.status !== 'active') return res.status(403).json({ ok: false, error: 'License inactive.' })
  if (license.expires_at && new Date(license.expires_at) < new Date()) return res.status(403).json({ ok: false, error: 'License expired.' })
  if (!license.hwid && hwid) {
    await query('UPDATE licenses SET hwid = $1, last_verified_at = NOW(), last_app_version = $2 WHERE id = $3', [hwid, appVersion || null, license.id])
    license.hwid = hwid
  } else {
    await query('UPDATE licenses SET last_verified_at = NOW(), last_app_version = $1 WHERE id = $2', [appVersion || null, license.id])
  }
  if (license.hwid && hwid && license.hwid !== hwid) return res.status(403).json({ ok: false, error: 'License already used on another PC.' })
  res.json({ ok: true, status: license.status, plan: license.plan_id, premium: license.premium, expires_at: license.expires_at })
}))

app.get('/api/download/:kind', auth, asyncHandler(async (req, res) => {
  const ok = await userHasActiveLicense(req.user.id)
  if (!ok) return res.status(403).json({ error: 'Active license required.' })
  const file = req.params.kind === 'msi' ? 'eqy-tweak-installer.msi' : 'eqy-tweak-setup.exe'
  res.download(path.join(__dirname, 'downloads', file))
}))

app.get('/latest.json', (_, res) => res.sendFile(path.join(__dirname, 'downloads', 'latest.json')))

app.post('/api/admin/login', authLimiter, asyncHandler(async (req, res) => {
  const secret = String(req.body.secret || '')
  if (!ADMIN_SECRET) return res.status(500).json({ error: 'ADMIN_SECRET is not configured on the backend.' })
  const expected = Buffer.from(ADMIN_SECRET)
  const received = Buffer.from(secret)
  if (expected.length !== received.length || !crypto.timingSafeEqual(expected, received)) return res.status(401).json({ error: 'Invalid admin secret.' })
  res.json({ token: signAdmin() })
}))

app.get('/api/admin/overview', adminAuth, asyncHandler(async (_, res) => {
  const users = await query(`SELECT u.id, u.email, u.created_at, COUNT(l.id)::int AS license_count FROM users u LEFT JOIN licenses l ON l.user_id = u.id GROUP BY u.id ORDER BY u.created_at DESC LIMIT 250`)
  const licenses = await query(`SELECT l.id, l.key, l.plan_id, l.status, l.hwid, l.expires_at, l.premium, l.created_at, u.email FROM licenses l LEFT JOIN users u ON u.id = l.user_id ORDER BY l.created_at DESC LIMIT 300`)
  const hwidRequests = await query(`SELECT r.id, r.license_id, r.reason, r.status, r.created_at, r.reviewed_at, u.email, l.key AS license_key, l.plan_id FROM hwid_reset_requests r LEFT JOIN users u ON u.id = r.user_id LEFT JOIN licenses l ON l.id = r.license_id ORDER BY CASE WHEN r.status = 'pending' THEN 0 ELSE 1 END, r.created_at DESC LIMIT 300`)
  res.json({ users: users.rows, licenses: licenses.rows, hwidRequests: hwidRequests.rows })
}))

app.post('/api/admin/hwid-requests/:id/approve', adminAuth, asyncHandler(async (req, res) => {
  const id = Number(req.params.id)
  const found = await query(`SELECT r.*, u.email, l.key AS license_key FROM hwid_reset_requests r LEFT JOIN users u ON u.id = r.user_id LEFT JOIN licenses l ON l.id = r.license_id WHERE r.id = $1`, [id])
  if (!found.rows.length) return res.status(404).json({ error: 'Request not found.' })
  const request = found.rows[0]
  await query('UPDATE licenses SET hwid = NULL WHERE id = $1', [request.license_id])
  await query('UPDATE hwid_reset_requests SET status = $1, reviewed_at = NOW() WHERE id = $2', ['approved', id])
  await sendEmail({ to: request.email, subject: 'EQY HWID reset approved', html: emailShell('HWID reset approved', `<p>Your HWID reset request for license <strong style="color:#fff;">${request.license_key}</strong> has been approved.</p><p>You can now activate the license on your new device.</p>`) })
  res.json({ ok: true, message: 'HWID reset approved and license HWID cleared.' })
}))

app.post('/api/admin/hwid-requests/:id/decline', adminAuth, asyncHandler(async (req, res) => {
  const id = Number(req.params.id)
  const found = await query(`SELECT r.*, u.email, l.key AS license_key FROM hwid_reset_requests r LEFT JOIN users u ON u.id = r.user_id LEFT JOIN licenses l ON l.id = r.license_id WHERE r.id = $1`, [id])
  if (!found.rows.length) return res.status(404).json({ error: 'Request not found.' })
  await query('UPDATE hwid_reset_requests SET status = $1, reviewed_at = NOW() WHERE id = $2', ['declined', id])
  await sendEmail({ to: found.rows[0].email, subject: 'EQY HWID reset declined', html: emailShell('HWID reset declined', `<p>Your HWID reset request for license <strong style="color:#fff;">${found.rows[0].license_key}</strong> was declined.</p><p>If you think this is a mistake, contact support.</p>`) })
  res.json({ ok: true, message: 'HWID reset request declined.' })
}))

app.post('/api/admin/licenses/:id/reset-hwid', adminAuth, asyncHandler(async (req, res) => {
  const found = await query(`SELECT l.*, u.email FROM licenses l LEFT JOIN users u ON u.id = l.user_id WHERE l.id = $1`, [Number(req.params.id)])
  await query('UPDATE licenses SET hwid = NULL WHERE id = $1', [Number(req.params.id)])
  if (found.rows[0]?.email) await sendEmail({ to: found.rows[0].email, subject: 'EQY HWID reset completed', html: emailShell('HWID reset completed', `<p>Your license HWID was reset by support.</p><p>License: <strong style="color:#fff;">${found.rows[0].key}</strong></p>`) })
  res.json({ ok: true, message: 'License HWID reset.' })
}))

app.post('/api/admin/licenses/:id/revoke', adminAuth, asyncHandler(async (req, res) => {
  const found = await query(`SELECT l.*, u.email FROM licenses l LEFT JOIN users u ON u.id = l.user_id WHERE l.id = $1`, [Number(req.params.id)])
  await query('UPDATE licenses SET status = $1 WHERE id = $2', ['revoked', Number(req.params.id)])
  if (found.rows[0]?.email) await sendEmail({ to: found.rows[0].email, subject: 'EQY license revoked', html: emailShell('License revoked', `<p>Your license has been revoked.</p><p>License: <strong style="color:#fff;">${found.rows[0].key}</strong></p>`) })
  res.json({ ok: true, message: 'License revoked.' })
}))

app.post('/api/admin/licenses/create', adminAuth, asyncHandler(async (req, res) => {
  const email = req.body.email ? String(req.body.email).toLowerCase().trim() : null
  const days = req.body.days ? Math.max(1, Number(req.body.days)) : null
  const premium = Boolean(req.body.premium)
  const planId = req.body.planId ? String(req.body.planId) : `${premium ? 'premium' : 'standard'}_${days ? `${days}d` : 'lifetime'}`
  let userId = null
  if (email) {
    const user = await query('SELECT id FROM users WHERE email = $1', [email])
    if (user.rows.length) userId = user.rows[0].id
  }
  const key = generateLicenseKey(planId)
  const expiresAt = days ? addDays(days) : null
  const created = await query('INSERT INTO licenses(user_id, key, plan_id, status, expires_at, premium) VALUES($1,$2,$3,$4,$5,$6) RETURNING *', [userId, key, planId, 'active', expiresAt, premium])
  if (email) await sendEmail({ to: email, subject: 'Your EQY license key', html: licenseEmailHtml({ key, planId, premium, expiresAt }) })
  res.json({ ok: true, license: created.rows[0], message: `License created: ${key}` })
}))

app.use((err, req, res, next) => {
  console.error(err)
  res.status(500).json({ error: err.message || 'Server error.' })
})

await initDb()
app.listen(PORT, () => console.log(`EQY backend running on ${PORT}`))

app.get('/api/test-email', async (_, res) => {
  try {
    const data = await resend.emails.send({
      from: EMAIL_FROM,
      to: EMAIL_ADMIN,
      subject: 'EQY Test Email',
      html: '<h1>EQY email system works ✅</h1><p>This is a test from your backend.</p>',
    })

    res.json({ ok: true, data })
  } catch (e) {
    console.error('[test email failed]', e)
    res.status(500).json({ ok: false, error: e.message })
  }
})
