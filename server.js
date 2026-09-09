require('dotenv').config()
const express = require('express')
const cors = require('cors')
const mongoose = require('mongoose')

const chittyRoutes = require('./routes/chittys')
const memberRoutes = require('./routes/members')

if (!process.env.MONGODB_URI || !process.env.JWT_SECRET) {
  console.error('Missing MONGODB_URI or JWT_SECRET — copy .env.example to .env and fill it in.')
  process.exit(1)
}

const app = express()
app.use(cors({ origin: process.env.FRONTEND_ORIGIN || '*' }))
app.use(express.json({ limit: '8mb' })) // raised from the 100KB default so a QR code image upload fits

app.get('/api/health', (req, res) => res.json({ ok: true }))
app.use('/api/chittys', chittyRoutes)
app.use('/api/members', memberRoutes)

app.use((err, req, res, next) => {
  console.error(err)
  res.status(500).json({ message: 'Something went wrong on the server.' })
})

const PORT = process.env.PORT || 5000

mongoose.connect(process.env.MONGODB_URI)
  .then(() => app.listen(PORT, () => console.log(`Chitty Book API running on port ${PORT}`)))
  .catch(err => { console.error('Failed to connect to MongoDB:', err.message); process.exit(1) })
