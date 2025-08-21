import express from 'express'
import bcrypt from 'bcrypt'
import jwt from 'jsonwebtoken'
import path from 'path'
import { fileURLToPath } from 'url'
import { readJSON, writeJSON } from '../utils/fileDb.js'
import dotenv from 'dotenv'

dotenv.config()

const router = express.Router()

const __filename = fileURLToPath(import.meta.url)
const __dirname = path.dirname(__filename)
const usersFile = path.join(__dirname, '..', 'data', 'users.json')

// (DEV helpers were removed)

function generateAccessToken(user) {
  return jwt.sign(
    { id: user.id, role: user.role, email: user.email },
    process.env.JWT_SECRET,
    { expiresIn: process.env.ACCESS_EXPIRES }
  )
}

function generateRefreshToken(user) {
  return jwt.sign({ id: user.id }, process.env.JWT_REFRESH_SECRET, {
    expiresIn: process.env.REFRESH_EXPIRES,
  })
}

// Логін користувача

router.post('/login', async (req, res) => {
  const { email, password } = req.body
  const users = await readJSON(usersFile)
  const user = users.find((u) => u.email == email)

  if (!user) return res.status(401).json({ error: 'Invalid credentials' })

  const passwordMatch = await bcrypt.compare(String(password ?? ''), String(user.password ?? ''))
  if (!passwordMatch) return res.status(401).json({ error: 'Invalid credentials' })

  // 5. Генеруємо accessToken і refreshToken
  const accessToken = generateAccessToken(user)
  const refreshToken = generateRefreshToken(user)

  // 6. Відправляємо refreshToken у httpOnly cookie, а accessToken і дані користувача — у відповідь
  res
    .cookie('refreshToken', refreshToken, {
      httpOnly: true,
      secure: false, // у проді — true
      sameSite: 'strict',
      maxAge: 7 * 24 * 60 * 60 * 1000,
    })
    .json({
      user: { id: user.id, email: user.email, role: user.role },
      accessToken,
    })
})

// Оновлення accessToken за допомогою refreshToken

router.post('/refresh', async (req, res) => {
  const token = req.cookies.refreshToken
  if (!token) return res.status(401).json({ error: 'Unauthorized', message: 'Missing refresh token' })
  try {
    const payload = jwt.verify(token, process.env.JWT_REFRESH_SECRET)
    const users = await readJSON(usersFile)
    const user = users.find((u) => u.id == payload.id)
    if (!user) return res.status(401).json({ error: 'Unauthorized', message: 'User not found' })
    const accessToken = generateAccessToken(user)
    res.json({ user: { id: user.id, email: user.email, role: user.role }, accessToken })
  } catch {
    return res.status(403).json({ error: 'Forbidden', message: 'Invalid or expired refresh token' })
  }
})

router.post('/logout', (req, res) => {
  res.clearCookie('refreshToken')
  res.sendStatus(204)
})

export default router
