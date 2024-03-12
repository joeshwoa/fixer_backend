const express = require("express");
const {
  signupValidator,
  loginByCodeValidator,
} = require("../utils/validator/authValidator");

const {
  signup,
  loginByCarCode,
  forgotPassword,
} = require("../services/authService");

const router = express.Router();

router.post("/signup", signup);
//router.post("/login", loginValidator, login);
router.post("/loginByCode", loginByCodeValidator, loginByCarCode);
router.post("/forgotPassword", forgotPassword);
//router.post("/verifyResetCode", verifyPassResetCode);
//router.put("/resetPassword", resetPassword);

module.exports = router;
