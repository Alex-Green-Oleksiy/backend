import express from 'express'
import cors from 'cors'
import cookieParser from 'cookie-parser'
import dotenv from 'dotenv'
import { delay } from './middleware/delay.js'

import authRoutes from './routes/auth.js'
import userRoutes from './routes/users.js'
import postRoutes from './routes/posts.js'
import commentRoutes from './routes/comments.js'

dotenv.config()

const app = express()

// CORS: allow from env (comma-separated). If not set, reflect request origin.
const allowedOrigins = (process.env.ALLOWED_ORIGINS || '')
  .split(',')
  .map((s) => s.trim())
  .filter(Boolean)

const corsOptions = {
  origin: allowedOrigins.length ? allowedOrigins : true,
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Authorization', 'Content-Type'],
}

app.use(cors(corsOptions))
// Handle preflight for all routes
app.options('*', cors(corsOptions))

app.use(express.json())
app.use(cookieParser())
app.use(delay)

app.use('/api/auth', authRoutes)
app.use('/api/users', userRoutes)
app.use('/api/posts', postRoutes)
app.use('/api/comments', commentRoutes)

const PORT = process.env.PORT || 4000
app.listen(PORT, () => console.log(`API listening on port ${PORT}`))
