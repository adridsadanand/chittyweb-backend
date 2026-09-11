const express = require('express')
const bcrypt = require('bcryptjs')
const rateLimit = require('express-rate-limit')
const Chitty = require('../models/Chitty')
const MemberAccount = require('../models/MemberAccount')
const { sendEmail, maskEmail } = require('../utils/email')
const { signToken, requireAuth, requireAdmin } = require('../middleware/auth')
const { normMobile, getCycleKey, getUnpaidList, generateUniqueCode, generateSixDigitCode, generateRecoveryCode, serializeChittyWithLoginStatus } = require('../utils/helpers')

const router = express.Router()
const authLimiter = rateLimit({ windowMs: 15 * 60 * 1000, max: 30, standardHeaders: true, legacyHeaders: false })

/* ---------- CREATE ---------- */
router.post('/', authLimiter, async (req, res) => {
  try {
    const { name, durationMonths, amountPerPerson, firstDrawISO, passcode, adminEmail } = req.body
    if (!name || !durationMonths || !amountPerPerson || !firstDrawISO || !passcode) {
      return res.status(400).json({ message: 'Please fill in every field.' })
    }
    const code = await generateUniqueCode(name)
    const passcodeHash = await bcrypt.hash(passcode, 10)
    const recoveryCode = generateRecoveryCode()
    const recoveryCodeHash = await bcrypt.hash(recoveryCode, 10)
    const chitty = await Chitty.create({
      code, name, durationMonths, amountPerPerson,
      passcodeHash, recoveryCodeHash, adminEmail: (adminEmail || '').trim(),
      createdDate: new Date().toISOString().slice(0, 10),
      nextDrawISO: firstDrawISO, participants: [], draws: [], payments: {}
    })
    const token = signToken({ chittyId: chitty.id.toString(), role: 'admin' })
    res.json({ chitty: await serializeChittyWithLoginStatus(chitty), token, recoveryCode })
  } catch (e) {
    res.status(500).json({ message: 'Could not create chitty.' })
  }
})

/* ---------- EMAIL THE SAVED GROUP CODE + RECOVERY CODE (fired when the
   admin taps "I've saved these — Continue" right after creating a group).
   The plain recoveryCode only ever exists for this one moment — only its
   hash is stored — so the client (which just received it) has to pass it
   back in here to be emailed; it can't be re-fetched later. ---------- */
router.post('/:id/email-setup-info', requireAuth, requireAdmin, async (req, res) => {
  try {
    const chitty = await Chitty.findById(req.params.id)
    if (!chitty) return res.status(404).json({ message: 'Chitty not found.' })
    const adminEmail = (chitty.adminEmail || '').trim()
    if (!adminEmail) return res.json({ emailed: false })

    const { recoveryCode } = req.body
    await sendEmail(
      adminEmail,
      `Your "${chitty.name}" group & recovery codes`,
      `Group code (share with members): ${chitty.code}\n` +
      `Recovery code (keep private — only you use this): ${recoveryCode || '(not provided)'}\n\n` +
      `Keep this email somewhere safe. You'll need the recovery code only if you ever forget your admin passcode.`
    )
    res.json({ emailed: true, maskedEmail: maskEmail(adminEmail) })
  } catch (e) {
    // Don't fail the whole flow over a flaky email send — the admin still has
    // the codes on screen and can copy them manually.
    res.json({ emailed: false })
  }
})

/* ---------- ADMIN LOGIN ---------- */
router.post('/login', authLimiter, async (req, res) => {
  try {
    const { code, passcode } = req.body
    if (!code || !passcode) return res.status(400).json({ message: 'Enter the chitty code and passcode.' })
    const chitty = await Chitty.findOne({ code: code.toUpperCase() })
    if (!chitty) return res.status(401).json({ message: 'Chitty code or passcode not recognised.' })
    const ok = await bcrypt.compare(passcode, chitty.passcodeHash)
    if (!ok) return res.status(401).json({ message: 'Chitty code or passcode not recognised.' })
    const token = signToken({ chittyId: chitty._id.toString(), role: 'admin' })
    res.json({ chitty: await serializeChittyWithLoginStatus(chitty), token })
  } catch (e) {
    res.status(500).json({ message: 'Could not sign in.' })
  }
})

/* ---------- RECOVER A FORGOTTEN PASSCODE (using the one-time recovery code) ---------- */
router.post('/recover-passcode', authLimiter, async (req, res) => {
  try {
    const { code, recoveryCode, newPasscode } = req.body
    if (!code || !recoveryCode || !newPasscode) {
      return res.status(400).json({ message: 'Fill in the group code, recovery code, and a new passcode.' })
    }
    const chitty = await Chitty.findOne({ code: code.toUpperCase() })
    if (!chitty) return res.status(404).json({ message: 'Group code not recognised.' })
    const ok = await bcrypt.compare(recoveryCode, chitty.recoveryCodeHash)
    if (!ok) return res.status(401).json({ message: 'That recovery code is incorrect.' })
    chitty.passcodeHash = await bcrypt.hash(newPasscode, 10)
    await chitty.save()
    const token = signToken({ chittyId: chitty._id.toString(), role: 'admin' })
    res.json({ chitty: await serializeChittyWithLoginStatus(chitty), token })
  } catch (e) {
    res.status(500).json({ message: 'Could not reset the passcode.' })
  }
})

/* ---------- RECOVER VIA EMAIL (backup path for admins who added a recovery
   email — useful if the recovery code itself has been lost too) ---------- */
router.post('/request-email-reset', authLimiter, async (req, res) => {
  try {
    const { code } = req.body
    if (!code) return res.status(400).json({ message: 'Enter your group code.' })
    const chitty = await Chitty.findOne({ code: code.toUpperCase() })
    if (!chitty) return res.status(404).json({ message: 'Group code not recognised.' })
    if (!chitty.adminEmail) {
      return res.status(400).json({ message: 'No recovery email is set for this group — use your recovery code instead.' })
    }
    const resetCode = generateSixDigitCode()
    chitty.emailResetCodeHash = await bcrypt.hash(resetCode, 10)
    chitty.emailResetCodeExpiresAt = new Date(Date.now() + 30 * 60 * 1000)
    await chitty.save()
    await sendEmail(
      chitty.adminEmail,
      'Your Chitty Book passcode reset code',
      `Someone requested a passcode reset for your group "${chitty.name}" (code ${chitty.code}).\n\nYour reset code is: ${resetCode}\n\nThis expires in 30 minutes. If this wasn't you, you can ignore this email — your passcode won't change unless this code is used.`
    )
    res.json({ sent: true, maskedEmail: maskEmail(chitty.adminEmail) })
  } catch (e) {
    res.status(500).json({ message: 'Could not send the reset email.' })
  }
})

router.post('/reset-passcode-via-email', authLimiter, async (req, res) => {
  try {
    const { code, resetCode, newPasscode } = req.body
    if (!code || !resetCode || !newPasscode) {
      return res.status(400).json({ message: 'Fill in every field.' })
    }
    const chitty = await Chitty.findOne({ code: code.toUpperCase() })
    if (!chitty || !chitty.emailResetCodeHash || !chitty.emailResetCodeExpiresAt) {
      return res.status(400).json({ message: 'No reset code found — request a new one first.' })
    }
    if (Date.now() > new Date(chitty.emailResetCodeExpiresAt).getTime()) {
      return res.status(400).json({ message: 'That code has expired — request a new one.' })
    }
    const ok = await bcrypt.compare(resetCode, chitty.emailResetCodeHash)
    if (!ok) return res.status(401).json({ message: 'That reset code is incorrect.' })
    chitty.passcodeHash = await bcrypt.hash(newPasscode, 10)
    chitty.emailResetCodeHash = null
    chitty.emailResetCodeExpiresAt = null
    await chitty.save()
    const token = signToken({ chittyId: chitty._id.toString(), role: 'admin' })
    res.json({ chitty: await serializeChittyWithLoginStatus(chitty), token })
  } catch (e) {
    res.status(500).json({ message: 'Could not reset the passcode.' })
  }
})

/* ---------- GET CHITTY ---------- */
router.get('/:id', requireAuth, async (req, res) => {
  const chitty = await Chitty.findById(req.params.id)
  if (!chitty) return res.status(404).json({ message: 'Chitty not found.' })
  res.json({ chitty: await serializeChittyWithLoginStatus(chitty) })
})

/* ---------- QR CODE (fetched separately from the main chitty payload,
   only when the Payments tab is actually open — keeps the frequent
   background poll from re-downloading this image every few seconds) ---------- */
router.get('/:id/qr-code', requireAuth, async (req, res) => {
  const chitty = await Chitty.findById(req.params.id).select('qrCodeDataUrl')
  if (!chitty) return res.status(404).json({ message: 'Chitty not found.' })
  res.json({ qrCodeDataUrl: chitty.qrCodeDataUrl || '' })
})

/* ---------- PARTICIPANTS ---------- */
router.post('/:id/participants', requireAuth, requireAdmin, async (req, res) => {
  const chitty = await Chitty.findById(req.params.id)
  if (!chitty) return res.status(404).json({ message: 'Chitty not found.' })
  const { name, mobile, amount, joinedDate } = req.body
  if (!name || !mobile) return res.status(400).json({ message: 'Name and mobile number are required.' })
  const normalized = normMobile(mobile)
  if (chitty.participants.some(p => p.normalizedMobile === normalized)) {
    return res.status(400).json({ message: 'This mobile number is already on the list.' })
  }
  chitty.participants.push({
    name, mobile, normalizedMobile: normalized,
    amount: amount || chitty.amountPerPerson, joinedDate: joinedDate || '',
    won: false, wonDate: null
  })
  await chitty.save()
  res.json({ chitty: await serializeChittyWithLoginStatus(chitty) })
})

router.post('/:id/participants/import', requireAuth, requireAdmin, async (req, res) => {
  const chitty = await Chitty.findById(req.params.id)
  if (!chitty) return res.status(404).json({ message: 'Chitty not found.' })
  const rows = Array.isArray(req.body.rows) ? req.body.rows : []
  let added = 0, skipped = 0
  const seen = new Set(chitty.participants.map(p => p.normalizedMobile))
  for (const r of rows) {
    const name = (r.name || '').toString().trim()
    const mobile = (r.mobile || '').toString().trim()
    const normalized = normMobile(mobile)
    if (!name || !mobile || seen.has(normalized)) { skipped++; continue }
    chitty.participants.push({
      name, mobile, normalizedMobile: normalized,
      amount: r.amount || chitty.amountPerPerson, joinedDate: r.joinedDate || '',
      won: false, wonDate: null
    })
    seen.add(normalized)
    added++
  }
  await chitty.save()
  res.json({ chitty: await serializeChittyWithLoginStatus(chitty), added, skipped })
})

router.delete('/:id/participants/:pid', requireAuth, requireAdmin, async (req, res) => {
  const chitty = await Chitty.findById(req.params.id)
  if (!chitty) return res.status(404).json({ message: 'Chitty not found.' })
  chitty.participants.id(req.params.pid)?.deleteOne()
  await chitty.save()
  res.json({ chitty: await serializeChittyWithLoginStatus(chitty) })
})

router.post('/:id/participants/:pid/mark-received', requireAuth, requireAdmin, async (req, res) => {
  const chitty = await Chitty.findById(req.params.id)
  if (!chitty) return res.status(404).json({ message: 'Chitty not found.' })
  const p = chitty.participants.id(req.params.pid)
  if (!p) return res.status(404).json({ message: 'Participant not found.' })
  const date = req.body.date || new Date().toISOString().slice(0, 10)
  p.won = true; p.wonDate = date
  chitty.draws.push({ winnerId: p._id.toString(), winnerName: p.name, date, method: 'manual-mark' })
  await chitty.save()
  res.json({ chitty: await serializeChittyWithLoginStatus(chitty) })
})

router.post('/:id/participants/:pid/undo-received', requireAuth, requireAdmin, async (req, res) => {
  const chitty = await Chitty.findById(req.params.id)
  if (!chitty) return res.status(404).json({ message: 'Chitty not found.' })
  const p = chitty.participants.id(req.params.pid)
  if (!p) return res.status(404).json({ message: 'Participant not found.' })
  p.won = false; p.wonDate = null
  chitty.draws = chitty.draws.filter(d => d.winnerId !== req.params.pid)
  await chitty.save()
  res.json({ chitty: await serializeChittyWithLoginStatus(chitty) })
})

/* ---------- MEMBER LOGIN SETUP CODE (admin-generated, free — no SMS) ----------
   The admin generates this and sends it to the member themselves (WhatsApp,
   call, text). It's a one-time, short-lived code that proves the admin
   vouches for this being that member's real number — free forever, no
   SMS provider needed. */
router.post('/:id/participants/:pid/generate-setup-code', requireAuth, requireAdmin, async (req, res) => {
  const chitty = await Chitty.findById(req.params.id)
  if (!chitty) return res.status(404).json({ message: 'Chitty not found.' })
  const p = chitty.participants.id(req.params.pid)
  if (!p) return res.status(404).json({ message: 'Participant not found.' })

  const code = generateSixDigitCode()
  const setupCodeHash = await bcrypt.hash(code, 10)
  const expiresAt = new Date(Date.now() + 30 * 60 * 1000) // 30 minutes

  await MemberAccount.findOneAndUpdate(
    { normalizedMobile: p.normalizedMobile },
    { normalizedMobile: p.normalizedMobile, setupCodeHash, setupCodeExpiresAt: expiresAt, failedPinAttempts: 0 },
    { upsert: true }
  )

  res.json({ code, expiresInMinutes: 30, name: p.name, mobile: p.mobile })
})

/* ---------- PAYMENTS ---------- */
router.post('/:id/payments/toggle', requireAuth, requireAdmin, async (req, res) => {
  const chitty = await Chitty.findById(req.params.id)
  if (!chitty) return res.status(404).json({ message: 'Chitty not found.' })
  const { participantId } = req.body
  const key = getCycleKey(chitty)
  if (!chitty.payments) chitty.payments = {}
  if (!chitty.payments[key]) chitty.payments[key] = {}
  chitty.payments[key][participantId] = !chitty.payments[key][participantId]
  chitty.markModified('payments')
  await chitty.save()
  res.json({ chitty: await serializeChittyWithLoginStatus(chitty) })
})

router.post('/:id/payments/mark-all-paid', requireAuth, requireAdmin, async (req, res) => {
  const chitty = await Chitty.findById(req.params.id)
  if (!chitty) return res.status(404).json({ message: 'Chitty not found.' })
  const key = getCycleKey(chitty)
  const map = {}
  chitty.participants.forEach(p => { map[p._id.toString()] = true })
  chitty.payments = chitty.payments || {}
  chitty.payments[key] = map
  chitty.markModified('payments')
  await chitty.save()
  res.json({ chitty: await serializeChittyWithLoginStatus(chitty) })
})

/* ---------- DRAW ---------- */
router.post('/:id/draw', requireAuth, requireAdmin, async (req, res) => {
  const chitty = await Chitty.findById(req.params.id)
  if (!chitty) return res.status(404).json({ message: 'Chitty not found.' })
  const unpaid = getUnpaidList(chitty)
  if (unpaid.length > 0) {
    return res.json({ postponed: true, unpaid: unpaid.map(p => ({ id: p._id.toString(), name: p.name })), chitty: await serializeChittyWithLoginStatus(chitty) })
  }
  const eligible = chitty.participants.filter(p => !p.won)
  if (eligible.length === 0) return res.json({ winner: null, chitty: await serializeChittyWithLoginStatus(chitty) })

  const winner = eligible[Math.floor(Math.random() * eligible.length)]
  winner.won = true
  winner.wonDate = new Date().toISOString().slice(0, 10)
  chitty.draws.push({ winnerId: winner._id.toString(), winnerName: winner.name, date: winner.wonDate, method: 'draw' })

  const base = chitty.nextDrawISO ? new Date(chitty.nextDrawISO) : new Date()
  base.setMonth(base.getMonth() + 1)
  chitty.nextDrawISO = base.toISOString()

  await chitty.save()
  res.json({ winner: { id: winner._id.toString(), name: winner.name }, chitty: await serializeChittyWithLoginStatus(chitty) })
})

/* ---------- SCHEDULE ---------- */
router.put('/:id/schedule', requireAuth, requireAdmin, async (req, res) => {
  const chitty = await Chitty.findById(req.params.id)
  if (!chitty) return res.status(404).json({ message: 'Chitty not found.' })
  const { nextDrawISO } = req.body
  if (!nextDrawISO) return res.status(400).json({ message: 'Pick a date and time first.' })
  chitty.nextDrawISO = nextDrawISO
  await chitty.save()
  res.json({ chitty: await serializeChittyWithLoginStatus(chitty) })
})

/* ---------- PAYMENT SETTINGS (UPI ID + QR code, shown to members on the Payments tab) ---------- */
router.put('/:id/settings', requireAuth, requireAdmin, async (req, res) => {
  const chitty = await Chitty.findById(req.params.id)
  if (!chitty) return res.status(404).json({ message: 'Chitty not found.' })
  const { upiId, qrCodeDataUrl, adminEmail } = req.body
  // A 6MB cap keeps a phone-camera QR photo well within MongoDB's 16MB
  // document size limit even after base64 overhead and everything else
  // already stored on this chitty.
  if (typeof qrCodeDataUrl === 'string' && qrCodeDataUrl.length > 6 * 1024 * 1024) {
    return res.status(400).json({ message: 'That image is too large — please use a smaller QR code image.' })
  }
  if (typeof upiId === 'string') chitty.upiId = upiId.trim()
  if (typeof qrCodeDataUrl === 'string') chitty.qrCodeDataUrl = qrCodeDataUrl
  if (typeof adminEmail === 'string') chitty.adminEmail = adminEmail.trim()
  await chitty.save()
  res.json({ chitty: await serializeChittyWithLoginStatus(chitty) })
})

/* ---------- RECOVERY SETTINGS (admin-only — email isn't shown to members) ---------- */
router.get('/:id/recovery-info', requireAuth, requireAdmin, async (req, res) => {
  const chitty = await Chitty.findById(req.params.id).select('adminEmail')
  if (!chitty) return res.status(404).json({ message: 'Chitty not found.' })
  res.json({ adminEmail: chitty.adminEmail || '' })
})

router.post('/:id/regenerate-recovery-code', requireAuth, requireAdmin, async (req, res) => {
  const chitty = await Chitty.findById(req.params.id)
  if (!chitty) return res.status(404).json({ message: 'Chitty not found.' })
  const recoveryCode = generateRecoveryCode()
  chitty.recoveryCodeHash = await bcrypt.hash(recoveryCode, 10)
  await chitty.save()
  // Same rule as at creation — this plaintext code only ever appears in
  // THIS response, never stored or retrievable again after this.
  res.json({ recoveryCode })
})

module.exports = router