const mongoose = require("mongoose");

const userSchema = new mongoose.Schema(
  {
    email: {
      type: String,
      require: true,
      max: 50,
      unique: true,
    },
    password: {
      type: String,
      require: true,
      min: 6,
    },
    isAdmin: {
      type: Boolean,
      default: false,
    },
    otp: { 
      type: String 
    },  // Lưu OTP tạm thời
    otpExpires: 
    { 
      type: Date,
      default: Date.now,
      expires: 300
    }  // Thời gian hết hạn OTP
  },
  { timestamps: true }
);

module.exports = mongoose.model("User", userSchema);
