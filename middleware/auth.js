const jwt = require('jsonwebtoken')

function signToken(payload) {
  return jwt.sign(payload, process.env.JWT_SECRET)
}

function requireAuth(req, res, next) {
  const header = req.headers.authorization || ''
  const token = header.startsWith('Bearer ') ? header.slice(7) : null
  if (!token) return res.status(401).json({ message: 'Sign in required.' })
  let payload
  try { payload = jwt.verify(token, process.env.JWT_SECRET) }
  catch (e) { return res.status(401).json({ message: 'Your session has expired — please sign in again.' }) }
  if (req.params.id && payload.chittyId !== req.params.id) {
    return res.status(403).json({ message: 'Not authorized for this chitty.' })
  }
  req.auth = payload
  next()
}

function requireAdmin(req, res, next) {
  if (req.auth?.role !== 'admin') return res.status(403).json({ message: 'Admin access required.' })
  next()
}

module.exports = { signToken, requireAuth, requireAdmin }
