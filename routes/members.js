const express = require('express')
const bcrypt = require('bcryptjs')
const rateLimit = require('express-rate-limit')
const Chitty = require('../models/Chitty')
const MemberAccount = require('../models/MemberAccount')
const { signToken } = require('../middleware/auth')
const { normMobile, isValidPin } = require('../utils/helpers')

const router = express.Router()
const authLimiter = rateLimit({ windowMs: 15 * 60 * 1000, max: 30, standardHeaders: true, legacyHeaders: false })

// Shared by /login and /verify-code — builds the per-chitty token list
// once someone's identity for this mobile number is confirmed.
async function buildMatches(mobile) {
  const chittys = await Chitty.find({ 'participants.normalizedMobile': mobile })
  return chittys.map(chitty => {
    const p = chitty.participants.find(x => x.normalizedMobile === mobile)
    return {
      chittyId: chitty._id.toString(),
      chittyName: chitty.name,
      code: chitty.code,
      participantId: p._id.toString(),
      token: signToken({ chittyId: chitty._id.toString(), role: 'member', participantId: p._id.toString() })
    }
  })
}

/* ---------- CHECK: does this number exist, and has it set a PIN yet? ---------- */
router.post('/check', authLimiter, async (req, res) => {
  const mobile = normMobile(req.body.mobile)
  if (mobile.length < 6) return res.status(400).json({ message: 'Enter a valid mobile number.' })

  const inAnyChitty = await Chitty.exists({ 'participants.normalizedMobile': mobile })
  if (!inAnyChitty) {
    return res.status(404).json({ message: "We couldn't find you — ask your group admin to add your number." })
  }
  const account = await MemberAccount.findOne({ normalizedMobile: mobile })
  res.json({ hasPin: !!(account && account.pinHash) })
})

/* ---------- LOGIN: mobile + PIN (once verified) ---------- */
router.post('/login', authLimiter, async (req, res) => {
  const mobile = normMobile(req.body.mobile)
  const { pin } = req.body
  const account = await MemberAccount.findOne({ normalizedMobile: mobile })
  if (!account || !account.pinHash) {
    return res.status(400).json({ message: 'Set up your PIN first using a code from your group admin.' })
  }
  if (account.failedPinAttempts >= 5) {
    return res.status(423).json({ message: 'Too many wrong attempts. Ask your group admin for a new setup code.' })
  }
  const ok = await bcrypt.compare(pin || '', account.pinHash)
  if (!ok) {
    account.failedPinAttempts += 1
    await account.save()
    return res.status(401).json({ message: 'Incorrect PIN.' })
  }
  account.failedPinAttempts = 0
  await account.save()
  const matches = await buildMatches(mobile)
  res.json({ matches })
})

/* ---------- VERIFY SETUP CODE + SET PIN (first time, or resetting a forgotten PIN) ---------- */
router.post('/verify-code', authLimiter, async (req, res) => {
  const mobile = normMobile(req.body.mobile)
  const { code, newPin } = req.body
  if (!isValidPin(newPin)) return res.status(400).json({ message: 'Choose a 4 to 6 digit PIN.' })

  const account = await MemberAccount.findOne({ normalizedMobile: mobile })
  if (!account || !account.setupCodeHash || !account.setupCodeExpiresAt) {
    return res.status(400).json({ message: 'No setup code found — ask your group admin to generate a new one.' })
  }
  if (Date.now() > new Date(account.setupCodeExpiresAt).getTime()) {
    return res.status(400).json({ message: 'That code has expired — ask your group admin for a new one.' })
  }
  const ok = await bcrypt.compare(code || '', account.setupCodeHash)
  if (!ok) return res.status(401).json({ message: 'That code is incorrect.' })

  account.pinHash = await bcrypt.hash(newPin, 10)
  account.setupCodeHash = null
  account.setupCodeExpiresAt = null
  account.failedPinAttempts = 0
  await account.save()

  const matches = await buildMatches(mobile)
  res.json({ matches })
})

module.exports = router
