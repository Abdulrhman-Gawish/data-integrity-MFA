const bcrypt = require("bcrypt");
const OTPAuth = require("otpauth");
const encode = require("hi-base32");
const QRCode = require("qrcode");
const speakeasy = require("speakeasy");
const User = require("../models/user");
const generateToken = require("../utils/generateTokenAndSetCookie");
const generateBase32Secret = require("../utils/generateBase32Secret");
const signUp = async (req, res) => {
  try {
    const { name, role, userName, password } = req.body;
    if (!name || !role || !userName || !password) {
      return res
        .status(400)
        .json({ success: false, message: "All failds are required" });
    }

    const userIsAlreadyExist = await User.findOne({ userName });
    if (userIsAlreadyExist) {
      return res
        .status(400)
        .json({ success: false, message: "User Already Exist" });
    }

    const hashedPassword = await bcrypt.hash(password, 10);
    const secret = speakeasy.generateSecret({ name: `${userName}` });

    const user = new User({
      name,
      role,
      userName,
      password: hashedPassword,
      twoFASecret: secret.base32,
    });
    // console.log("userr: ", user.twoFASecret);

    await user.save();
    const payload = {
      userId: user._id,
      role: user.role,
    };
    // jwt
    console.log(generateToken(payload, res));
    res.status(201).json({
      success: true,
      user: {
        ...user._doc,
        password: undefined,
      },
    });
  } catch (error) {
    console.log(error);
  }
};

const login = async (req, res) => {
  try {
    const { userName, password } = req.body;

    if ((!userName, !password)) {
      return res
        .status(400)
        .json({ success: false, message: "All failds are required" });
    }
    const user = await User.findOne({ userName });

    const passwordIsValid = await bcrypt.compare(password, user.password);

    if (!passwordIsValid) {
      res.status(400).json({ success: false, message: "Invalid credentials" });
    }
    const payload = {
      userId: user._id,
      userRole: user.role,
    };

    // jwt
    generateToken(payload, res);
    res.status(201).json({
      success: true,
      user: {
        ...user._doc,
        password: undefined,
      },
    });
  } catch (error) {
    console.log(error);
  }
};

const logout = (req, res) => {
  res.clearCookie("token");
  res.status(200).json({ success: true, message: "Cookies cleared" });
};

const checkAuth = async (req, res) => {
  try {
    console.log(req.userId);

    const user = await User.findById(req.userId).select("-password");
    if (!user) {
      return res
        .status(400)
        .json({ success: false, message: "User not found" });
    }

    res.status(200).json({ success: true, user });
  } catch (error) {
    console.log("Error in checkAtuh", error);
    res.status(500).json({ success: false, message: error.message });
  }
};

const enable2FA = async (req, res) => {
  try {
    const { userId } = req.body;

    if (!userId) {
      return res.status(400).json({
        success: false,
        message: "User ID is required",
      });
    }

    const user = await User.findById(userId);
    if (!user) {
      return res.status(404).json({
        success: false,
        message: "User not found",
      });
    }

    if (user.is2FAEnabled) {
      return res.status(400).json({
        success: false,
        message: "2FA is already enabled for this user",
      });
    }

    // Generate a new secret if not already set
    let secret = user.twoFASecret;
    if (!secret) {
      secret = speakeasy.generateSecret({
        name: `mgmt-task:${user.userName || user.email}`,
      });
      user.twoFASecret = secret.base32;
      await user.save();
    }

    const otpauth_url = speakeasy.otpauthURL({
      secret,
      label: user.userName || user.email,
      issuer: "mgmt-task",
      encoding: "base32",
    });

    // Generate QR code
    let qrCodeData;
    try {
      qrCodeData = await QRCode.toDataURL(otpauth_url);
    } catch (error) {
      console.error("QR generation failed:", error);
      return res.status(500).json({
        success: false,
        message: "Failed to generate QR code",
      });
    }
    res.status(200).json({
      success: true,
      message: "Scan the QR code to enable 2FA",
      data: {
        qr_code: qrCodeData,
        secret: secret.base32,
        otpauth_url: secret.otpauth_url,
      },
    });
  } catch (error) {
    console.error("Error in enable2FA:", error);
    res.status(500).json({
      success: false,
      message: "Internal server error",
    });
  }
};

const verify2FA = async (req, res) => {
  try {
    const { userId, token } = req.body;
    if (!userId || !token) {
      return res.status(400).json({
        success: false,
        message: "User ID and token are required",
      });
    }

    const user = await User.findById(userId);
    if (!user) {
      return res.status(404).json({
        success: false,
        message: "User not found",
      });
    }

    const verify = speakeasy.totp.verify({
      secret: user.twoFASecret,
      encoding: "base32",
      token,
      window: 1,
    });

    if (verify) {
      user.is2FAEnabled = true;
      await user.save();
      return res
        .status(200)
        .json({ success: true, message: "2FA authentication successful" });
    } else {
      return res
        .status(401)
        .json({ success: false, message: "2FA authentication failed" });
    }
  } catch (error) {
    console.error("Error in verufy2FA:", error);
    res.status(500).json({
      success: false,
      message: "Internal server error",
    });
  }
};

module.exports = {
  signUp,
  login,
  checkAuth,
  logout,
  enable2FA,
  verify2FA,
};
