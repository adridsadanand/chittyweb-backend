const mongoose = require('mongoose')
const { Schema } = mongoose

const ParticipantSchema = new Schema({
  name: { type: String, required: true, trim: true },
  mobile: { type: String, required: true, trim: true },
  normalizedMobile: { type: String, required: true, index: true },
  amount: { type: Schema.Types.Mixed, default: null },
  joinedDate: { type: String, default: '' },
  won: { type: Boolean, default: false },
  wonDate: { type: String, default: null }
})

const DrawSchema = new Schema({
  winnerId: { type: String, required: true },
  winnerName: { type: String, required: true },
  date: { type: String, required: true },
  method: { type: String, enum: ['draw', 'manual-mark'], required: true }
})

const ChittySchema = new Schema({
  code: { type: String, required: true, unique: true, uppercase: true },
  name: { type: String, required: true, trim: true },
  durationMonths: { type: Number, required: true },
  amountPerPerson: { type: Schema.Types.Mixed, required: true },
  passcodeHash: { type: String, required: true },
  recoveryCodeHash: { type: String, required: true },
  adminEmail: { type: String, default: '' }, // optional — enables email-based recovery as a backup to the recovery code
  emailResetCodeHash: { type: String, default: null },
  emailResetCodeExpiresAt: { type: Date, default: null },
  createdDate: { type: String, required: true },
  nextDrawISO: { type: String, default: null },
  upiId: { type: String, default: '' },
  qrCodeDataUrl: { type: String, default: '' }, // small base64 PNG/JPEG the admin uploads — no file storage needed
  participants: { type: [ParticipantSchema], default: [] },
  draws: { type: [DrawSchema], default: [] },
  payments: { type: Schema.Types.Mixed, default: {} }
}, { timestamps: true })

ChittySchema.set('toJSON', {
  virtuals: true,
  transform(doc, ret) {
    ret.id = ret._id.toString()
    delete ret._id
    delete ret.__v
    delete ret.passcodeHash
    delete ret.recoveryCodeHash
    delete ret.adminEmail
    delete ret.emailResetCodeHash
    delete ret.emailResetCodeExpiresAt
    // The QR image is base64 (can be hundreds of KB) — excluded from the
    // normal chitty payload so the frequent background poll doesn't
    // re-download it every few seconds. Fetched separately via
    // GET /chittys/:id/qr-code only when the Payments tab is actually open.
    delete ret.qrCodeDataUrl
    if (Array.isArray(ret.participants)) {
      ret.participants = ret.participants.map(p => {
        const { _id, normalizedMobile, ...rest } = p
        return { id: _id.toString(), ...rest }
      })
    }
    if (Array.isArray(ret.draws)) {
      ret.draws = ret.draws.map(d => { const { _id, ...rest } = d; return rest })
    }
    return ret
  }
})

module.exports = mongoose.model('Chitty', ChittySchema)
