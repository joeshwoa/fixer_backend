const crypto = require("crypto");

const jwt = require("jsonwebtoken");
const bcrypt = require("bcryptjs");
const Car = require("../models/Car");
const asyncHandler = require("express-async-handler");
const ApiError = require("../utils/apiError");
const sendEmail = require("../utils/sendEmail");
const createToken = require("../utils/createToken");

const User = require("../models/userModel");

// Function to generate a unique 8-digit code
const generateUniqueCode = async () => {
  let isUnique = false;
  let code;

  // Generate and check until a unique 8-digit code is found
  while (!isUnique) {
    code = Math.floor(10000000 + Math.random() * 90000000).toString();
    const existingCar = await Car.findOne({ generatedCode: code });

    if (!existingCar) {
      isUnique = true;
    }
  }

  return code;
};
// @desc    Signup
// @route   GET /api/v1/auth/signup
// @access  Public
exports.signup = asyncHandler(async (req, res, next) => {
  const generatedCode = await generateUniqueCode();
  const generatedPassword = crypto.randomBytes(6).toString("hex").toUpperCase();
  //console.log("generated code", generatedCode);
  //console.log("generated Password", generatedPassword);
  // 1- Create user
  const newCar = await Car.create({
    ownerName: req.body.name,
    carNumber: req.body.carNumber,
    phoneNumber: req.body.phoneNumber,
    email: req.body.email,
    carIdNumber: req.body.carIdNumber,
    color: req.body.color,
    brand: req.body.brand,
    category: req.body.category,
    model: req.body.model,
    generatedCode: generatedCode,
    generatedPassword: generatedPassword,
  });
  const user = await User.create({
    name: req.body.name,
    email: req.body.email,
    password: generatedPassword,
    Car: newCar._id, // Assuming your user schema has a 'car' field to store the car reference
    carCode: generatedCode,
  });

  // 2- Generate token
  const token = createToken(user._id);
  // 3) Send the reset code via email
  const message = `Dear ${user.name},\n\nYour car has been successfully registered with us.\n\nHere are your credentials:\nCode: ${newCar.generatedCode}\nPassword: ${newCar.generatedPassword}\n\nThank you for choosing our service.\n\nBest regards,\nThe Car Service Center Team`;
  try {
    await sendEmail({
      email: user.email,
      subject: "Your password",
      message,
    });
    res
      .status(200)
      .json({ status: "Success", message: "Reset code sent to email" });
  } catch (err) {
    return next(new ApiError("There is an error in sending email", 500));
  }
  res.status(201).json({ data: user, token });
});

// @desc    Login using car code
// @route   GET /api/v1/auth/loginByCarCode
// @access  Public
exports.loginByCarCode = asyncHandler(async (req, res, next) => {
  // 1) check if password and email in the body (validation)
  // 2) check if user exist & check if password is correct
  const user = await User.findOne({ carCode: req.body.carCode });
  if (!user || !(await bcrypt.compare(req.body.password, user.password))) {
    return next(new ApiError("Incorrect carCode or password", 401));
  }
  // 3) generate token
  const token = createToken(user._id);

  // Delete password from response
  delete user._doc.password;
  // 4) send response to client side
  res.status(200).json({ data: user, token });
});

// @desc   make sure the user is logged in
exports.protect = asyncHandler(async (req, res, next) => {
  // 1) Check if token exist, if exist get
  let token;
  if (
    req.headers.authorization &&
    req.headers.authorization.startsWith("Bearer")
  ) {
    token = req.headers.authorization.split(" ")[1];
  }
  if (!token) {
    return next(
      new ApiError(
        "You are not login, Please login to get access this route",
        401
      )
    );
  }

  // 2) Verify token (no change happens, expired token)
  const decoded = jwt.verify(token, process.env.JWT_SECRET_KEY);

  // 3) Check if user exists
  const currentUser = await User.findById(decoded.userId);
  if (!currentUser) {
    return next(
      new ApiError(
        "The user that belong to this token does no longer exist",
        401
      )
    );
  }

  // 4) Check if user change his password after token created
  if (currentUser.passwordChangedAt) {
    const passChangedTimestamp = parseInt(
      currentUser.passwordChangedAt.getTime() / 1000,
      10
    );
    // Password changed after token created (Error)
    if (passChangedTimestamp > decoded.iat) {
      return next(
        new ApiError(
          "User recently changed his password. please login again..",
          401
        )
      );
    }
  }

  req.user = currentUser;
  next();
});

// @desc    Authorization (User Permissions)
// ["admin", "manager"]
exports.allowedTo = (...roles) =>
  asyncHandler(async (req, res, next) => {
    // 1) access roles
    // 2) access registered user (req.user.role)
    if (!roles.includes(req.user.role)) {
      return next(
        new ApiError("You are not allowed to access this route", 403)
      );
    }
    next();
  });
// @desc    Forgot password
// @route   POST /api/v1/auth/forgotPassword
// @access  Public
exports.forgotPassword = asyncHandler(async (req, res, next) => {
  // 1) Get user by email
  console.log(await User.findOne({ carCode: req.body.carCode }));
  const user = await User.findOne({ carCode: req.body.carCode });
  if (!user) {
    return next(
      new ApiError(`There is no user with that code ${req.body.carCode}`, 404)
    );
  }
  console.log(user.carCode);
  console.log(user.password);
  oldPassword = crypto.de(user.password);
  console.log(oldPassword);
  // 2) If user exist, Generate hash reset random 6 digits and save it in db
  //const resetCode = Math.floor(100000 + Math.random() * 900000).toString();
  const hashedpassword = crypto
    .createHash("sha256")
    .update(user.password)
    .digest("hex");

  // Save hashed password reset code into db
  user.passwordResetCode = hashedResetCode;
  // Add expiration time for password reset code (10 min)
  //user.passwordResetExpires = Date.now() + 10 * 60 * 1000;
  //user.passwordResetVerified = false;

  await user.save();
  // 3) Send the reset code via email
  const message = `Dear ${user.name},\n\nHere are your credentials:\nCode: ${Car.generatedCode}\nPassword: ${user.password}\n\nThank you for choosing our service.\n\nBest regards,\nThe Car Service Center Team`;
  try {
    await sendEmail({
      email: user.email,
      subject: "Your old password",
      message,
    });
    res
      .status(200)
      .json({ status: "Success", message: "Reset code sent to email" });
  } catch (err) {
    user.passwordResetCode = undefined;
    user.passwordResetExpires = undefined;
    user.passwordResetVerified = undefined;

    await user.save({ validateBeforeSave: false });
    return next(new ApiError("There is an error in sending email", 500));
  }
});
