const mongoose = require("mongoose");
//const bcrypt = require("bcryptjs");

const userSchema = new mongoose.Schema(
  {
    name: {
      type: String,
      trim: true,
      required: [true, "name required"],
    },
    slug: {
      type: String,
      lowercase: true,
    },
    email: {
      type: String,
      required: [true, "email required"],
      unique: true,
      lowercase: true,
    },
    phone: String,
    profileImg: String,

    password: {
      type: String,
      minlength: [6, "Too short password"],
    },
    passwordChangedAt: Date,
    passwordResetCode: String,
    passwordResetExpires: Date,
    passwordResetVerified: Boolean,
    role: {
      type: String,
      enum: ["user", "manager", "admin"],
      default: "user",
    },
    active: {
      type: Boolean,
      default: true,
    },
    Car: {
      type: mongoose.Schema.ObjectId,
      ref: "Car",
      required: [true, "car owner must have generated Car Code"],
    },
    carCode: {
      type: String,
      unique: true,
      maxlength: 8,
    },
  },
  { timestamps: true }
);

//userSchema.pre("save", async function (next) {
// if (!this.isModified("password")) return next();
// Hashing user password
//  this.password = await bcrypt.hash(this.password, 12);
//  next();
//});

const User = mongoose.model("User", userSchema);

module.exports = User;
