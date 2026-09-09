const mongoose = require('mongoose')
const { Schema } = mongoose

/* One account per mobile number, shared across every chitty that number
   is a member of. This is deliberately separate from Chitty.participants —
   participants are membership/financial records per group, this is the
   person's login credentials, verified once and reused everywhere.

   No SMS provider involved: "setupCodeHash" is a one-time code the GROUP
   ADMIN generates and shares with the member directly (WhatsApp, call,
   whatever) — completely free, and fits how these small trusted circles
   already communicate. */
const MemberAccountSchema = new Schema({
  normalizedMobile: { type: String, required: true, unique: true, index: true },
  pinHash: { type: String, default: null },
  setupCodeHash: { type: String, default: null },
  setupCodeExpiresAt: { type: Date, default: null },
  failedPinAttempts: { type: Number, default: 0 }
}, { timestamps: true })

module.exports = mongoose.model('MemberAccount', MemberAccountSchema)
