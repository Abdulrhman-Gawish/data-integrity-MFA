const User = require("../models/user");
const bcrypt = require("bcrypt");
const generateToken = require("../utils/generateTokenAndSetCookie");
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

    const user = new User({
      name,
      role,
      userName,
      password: hashedPassword,
    });

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

module.exports = {
  signUp,
  login,
  checkAuth,
  logout,
};
