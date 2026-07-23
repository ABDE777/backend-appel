const bcrypt = require('bcryptjs');

const password = process.argv[2] || 'admin123';
const hash = bcrypt.hashSync(password, 12);

console.log(`Password: ${password}`);
console.log(`Hash: ${hash}`);
