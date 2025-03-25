const mongoose = require("mongoose");
const bcrypt = require("bcrypt");
const { Schema } = mongoose;
const userRole = require("../utils/enums/userRole");

const userSchema = new Schema({
  name: {
    type: String,
    required: true,
  },
  role: {
    type: String,
    enum: Object.values(userRole),
    default: userRole.CUSTOMER,
  },
  userName: {
    type: String,
    unique: true,
    required: true,
  },
  password: {
    type: String,
    required: true,
  },
  is2FAEnabled: { type: Boolean, default: false },
  twoFASecret: { type: String }, // Store the 2FA secret key
});

// userSchema.pre("save", async (next) => {
//   const salt = await bcrypt.genSalt(10);
//   await bcrypt.hash(this.password, salt);
//   next();
// });

const User = mongoose.model("User", userSchema);
module.exports = User;
