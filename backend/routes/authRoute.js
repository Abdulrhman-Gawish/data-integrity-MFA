const express = require("express");
const authController = require("../controller/authController");
const verifyToken = require("../middleware/verifyToken");
const router = express.Router();

router.route("/signup").post(authController.signUp);
router.route("/login").post(authController.login);
router.route("/logout").get(authController.logout);
router.route("/checkAuth").get(verifyToken, authController.checkAuth);

module.exports = router;
