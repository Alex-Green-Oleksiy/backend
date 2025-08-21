import bcrypt from 'bcrypt'

const pwd = process.argv[2]
if (!pwd) {
  console.error('Usage: node scripts/genHash.mjs <password>')
  process.exit(1)
}

const rounds = Number(process.argv[3] || 12)
const hash = await bcrypt.hash(pwd, rounds)
console.log(hash)
