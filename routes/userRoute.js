const express = require("express");
const {
  getUserValidator,
  createUserValidator,
  updateUserValidator,
  deleteUserValidator,
  changeUserPasswordValidator,
  updateLoggedUserValidator,
} = require("../utils/validator/userValidator");
const {
  getUsers,
  getUser,
  createUser,
  updateUser,
  makeUserUnactive,
  uploadUserImage,
  resizeImage,
  changeUserPassword,
  getLoggedUserData,
  updateLoggedUserPassword,
  updateLoggedUserData,
  deleteLoggedUserData,
} = require("../services/userService");

const authService = require("../services/authService");

const router = express.Router();

router.use(authService.protect);

//router.get("/getMe", getLoggedUserData, getUser);
//router.put("/changeMyPassword", updateLoggedUserPassword);
//router.put("/updateMe", updateLoggedUserValidator, updateLoggedUserData);
//router.delete("/deleteMe", deleteLoggedUserData);

// Admin
router.use(authService.allowedTo("admin", "manager"));
router.put(
  "/changePassword/:id",
  changeUserPasswordValidator,
  changeUserPassword
);
router
  .route("/")
  .get(getUsers)
  .post(uploadUserImage, resizeImage, createUserValidator, createUser);
router
  .route("/:id")
  .get(getUserValidator, getUser)
  .put(uploadUserImage, resizeImage, updateUserValidator, updateUser);
router.route("/active/:id").put(makeUserUnactive);

module.exports = router;
