const jwt = require("jsonwebtoken");

const generateToken = (payload, res) => {
  const token = jwt.sign(payload, process.env.JWT_SECRET, {
    expiresIn: "10m",
  });
  res.cookie("token", token, {
    httpOnly: true, // Prevents JavaScript access (security)
    secure: process.env.NODE_ENV === "production", // Use HTTPS in production
    sameSite: "strict", // Prevents CSRF attacks
    maxAge: 10 * 60 * 1000, // 10 minutes in milliseconds
  });
  return token;
};

module.exports = generateToken;
