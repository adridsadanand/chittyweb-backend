const nodemailer = require('nodemailer')

/* ============================================================
   Free email sending via Gmail SMTP.
   To enable it, add to your .env:
     GMAIL_USER=youraddress@gmail.com
     GMAIL_APP_PASSWORD=xxxx xxxx xxxx xxxx

   The app password is NOT your regular Gmail password — generate one at
   myaccount.google.com/apppasswords (requires 2-Step Verification turned
   on for that Google account first). This is completely free and works
   for reasonable volume — no email provider account needed.

   Until you set those two variables, this just prints the code to your
   server console instead — handy for testing locally without setting up
   email at all yet.
============================================================ */

let transporter = null
function getTransporter() {
  if (transporter) return transporter
  if (!process.env.GMAIL_USER || !process.env.GMAIL_APP_PASSWORD) return null
  transporter = nodemailer.createTransport({
    service: 'gmail',
    auth: { user: process.env.GMAIL_USER, pass: process.env.GMAIL_APP_PASSWORD }
  })
  return transporter
}

async function sendEmail(to, subject, text) {
  const t = getTransporter()
  if (!t) {
    console.log(`[DEV — email not configured] To: ${to} | Subject: ${subject}\n${text}`)
    return
  }
  try {
    const info = await t.sendMail({ from: process.env.GMAIL_USER, to, subject, text })
    console.log('[EMAIL SENT]', info.messageId, info.response)
  } catch (err) {
    console.error('[EMAIL FAILED]', err.message)
    throw err
  }
}

function maskEmail(email) {
  if (!email || !email.includes('@')) return ''
  const [user, domain] = email.split('@')
  const visible = user.slice(0, 2)
  return `${visible}${'*'.repeat(Math.max(1, user.length - 2))}@${domain}`
}

module.exports = { sendEmail, maskEmail }
