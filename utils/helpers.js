const Chitty = require('../models/Chitty')
const MemberAccount = require('../models/MemberAccount')

function normMobile(m) {
  return (m || '').toString().replace(/\D/g, '')
}

function getCycleKey(chitty) {
  const d = chitty.nextDrawISO ? new Date(chitty.nextDrawISO) : new Date()
  return d.getFullYear() + '-' + String(d.getMonth() + 1).padStart(2, '0')
}

function getUnpaidList(chitty) {
  const key = getCycleKey(chitty)
  const paidMap = (chitty.payments && chitty.payments[key]) || {}
  return chitty.participants.filter(p => !paidMap[p._id.toString()])
}

function isDrawOverdue(chitty) {
  return !!(chitty.nextDrawISO && Date.now() >= new Date(chitty.nextDrawISO).getTime())
}

async function generateUniqueCode(name) {
  const letters = (name || 'CHT').replace(/[^a-zA-Z]/g, '').toUpperCase().slice(0, 3).padEnd(3, 'X')
  let code, exists = true
  while (exists) {
    const num = Math.floor(100 + Math.random() * 900)
    code = letters + num
    exists = await Chitty.exists({ code })
  }
  return code
}

// A plain 6-digit numeric code — easy to read aloud or paste into a
// WhatsApp message, which is exactly how the admin will deliver it.
function generateSixDigitCode() {
  return String(Math.floor(100000 + Math.random() * 900000))
}

// A one-time recovery key shown ONLY at chitty creation — like a password
// manager's recovery key. This is the admin's only way back in if they
// forget their passcode, since there's no email/SMS in this free setup to
// verify their identity any other way. Formatted in groups for readability.
function generateRecoveryCode() {
  const chars = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789' // no O/0/I/1 — easy to misread otherwise
  const group = () => Array.from({ length: 4 }, () => chars[Math.floor(Math.random() * chars.length)]).join('')
  return `${group()}-${group()}-${group()}`
}

function isValidPin(pin) {
  return /^\d{4,6}$/.test(pin || '')
}

// Adds a `loginReady` flag to each participant — separate from `won`
// (the draw/payout status), this tells the admin whether that person has
// actually finished setting up their PIN yet, so the two ideas don't get
// visually mixed together in the UI.
async function serializeChittyWithLoginStatus(chittyDoc) {
  const idToMobile = new Map(chittyDoc.participants.map(p => [p._id.toString(), p.normalizedMobile]))
  const mobiles = [...new Set(idToMobile.values())]
  const accounts = await MemberAccount.find({ normalizedMobile: { $in: mobiles }, pinHash: { $ne: null } }, 'normalizedMobile')
  const verified = new Set(accounts.map(a => a.normalizedMobile))
  const json = chittyDoc.toJSON()
  json.participants = json.participants.map(p => ({ ...p, loginReady: verified.has(idToMobile.get(p.id)) }))
  return json
}

module.exports = { normMobile, getCycleKey, getUnpaidList, isDrawOverdue, generateUniqueCode, generateSixDigitCode, generateRecoveryCode, isValidPin, serializeChittyWithLoginStatus }
