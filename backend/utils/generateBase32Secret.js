const crypto = require("crypto");

function generateBase32Secret(length = 20) {
  const chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
  const randomBytes = crypto.randomBytes(length);
  let result = "";

  for (let i = 0; i < length; i++) {
    const byte = randomBytes[i];
    result += chars[byte % chars.length];
  }

  return result;
}

module.exports = generateBase32Secret;
