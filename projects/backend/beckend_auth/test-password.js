import bcrypt from 'bcrypt'

// Тестуємо хеш з users.json
const hash = '$2b$12$JK1rXHniD6/UXS.qlrBwTuz9kw09v1XZYfntjZ4MnS9e4G5v82r8S'
const password = '123456'

console.log('Testing password:', password)
console.log('Against hash:', hash)

bcrypt.compare(password, hash).then(result => {
  console.log('Password matches:', result)
  
  if (!result) {
    console.log('Creating new hash for password:', password)
    bcrypt.hash(password, 12).then(newHash => {
      console.log('New hash:', newHash)
    })
  }
}).catch(err => {
  console.error('Error:', err)
})
