import bcrypt from 'bcrypt'

async function createHash() {
  const password = '123456'
  const hash = await bcrypt.hash(password, 12)
  console.log('Password:', password)
  console.log('New hash:', hash)
  
  // Test the hash
  const isValid = await bcrypt.compare(password, hash)
  console.log('Hash is valid:', isValid)
}

createHash()
