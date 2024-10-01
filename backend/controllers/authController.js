const User = require("../models/User");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const sendEmail = require('../utils/sendEmail');
require("dotenv").config();

let refreshTokens = [];
// Helper function to generate OTP
const generateOTP = () => Math.floor(100000 + Math.random() * 900000).toString();

const authController = {
  //REGISTER
  registerUser: async (req, res) => {
    try {
      const salt = await bcrypt.genSalt(10);
      const hashed = await bcrypt.hash(req.body.password, salt);
      const otp = generateOTP();
      const otpExpires = Date.now()

      //Create new user
      const newUser = await new User({
        email: req.body.email,
        password: hashed,
        otp: otp,
        otpExpires: otpExpires
      });

      //Save user to DB
      const user = await newUser.save();
      await sendEmail(req.body.email, 'Your OTP Code', `Your OTP is ${otp}`);

      return res.status(200).json(user);
    } catch (err) {
      res.status(500).json(err);
    }
  },


  //VerifyOTP
  verifyOtp : async (req, res) => {
    const { email, otp } = req.body;
    try {
        const user = await User.findOne({ email });

        if (user.otp !== otp) {
        return res.status(400).send('Invalid or expired OTP');
        }

        // Clear OTP after successful verification
        user.otp = null;
        user.otpExpires = null;
        const newUser = await user.save();

        res.status(200).json(newUser);
    } catch (error) {
        res.status(500).send('Server error');
    }
  },

  generateAccessToken: (user) => {
    return jwt.sign(
      {
        id: user.id,
        isAdmin: user.isAdmin,
      },
      process.env.JWT_ACCESS_KEY,
      { expiresIn: "30s" }
    );
  },

  generateRefreshToken: (user) => {
    return jwt.sign(
      {
        id: user.id,
        isAdmin: user.isAdmin,
      },
      process.env.JWT_REFRESH_KEY,
      { expiresIn: "365d" }
    );
  },

  //LOGIN
  loginUser: async (req, res) => {
    try {
      const user = await User.findOne({ email: req.body.email });
      if (!user) {
        return res.status(404).json("Incorrect email");
      }
      const validPassword = await bcrypt.compare(
        req.body.password,
        user.password
      );
      if (!validPassword) {
        return res.status(404).json("Incorrect password");
      }
      if (user && validPassword) {
        //Generate access token
        const accessToken = authController.generateAccessToken(user);
        //Generate refresh token
        const refreshToken = authController.generateRefreshToken(user);

        refreshTokens.push(refreshToken);
        //STORE REFRESH TOKEN IN COOKIE
        res.cookie("refreshToken", refreshToken, {
          httpOnly: true,
          secure:false,
          path: "/",
          sameSite: "strict",
        }); 
        const {password, ...others} = user._doc;
        res.status(200).json({...others, accessToken, refreshToken});
      }
    }
     catch (err) {
      res.status(500).json(err);
    }
  },

  requestRefreshToken: async (req, res) => {
    //Take refresh token from user
    const refreshToken = req.cookies.refreshToken;
    //Send error if token is not valid
    if (!refreshToken) return res.status(401).json("You're not authenticated");
    if (!refreshTokens.includes(refreshToken)) {
      return res.status(403).json("Refresh token is not valid");
    }
    jwt.verify(refreshToken, process.env.JWT_REFRESH_KEY, (err, user) => {
      if (err) {
        console.log(err);
      }
      refreshTokens = refreshTokens.filter((token) => token !== refreshToken);
      //create new access token, refresh token and send to user
      const newAccessToken = authController.generateAccessToken(user);
      const newRefreshToken = authController.generateRefreshToken(user);
      refreshTokens.push(newRefreshToken);
      res.cookie("refreshToken", newRefreshToken, {
        httpOnly: true,
        secure:false,
        path: "/",
        sameSite: "strict",
      });
      res.status(200).json({
        accessToken: newAccessToken,
        refreshToken: newRefreshToken,
      });
    });
  },

  //LOG OUT
  logOut: async (req, res) => {
    //Clear cookies when user logs out
    refreshTokens = refreshTokens.filter((token) => token !== req.body.token);
    res.clearCookie("refreshToken");
    res.status(200).json("Logged out successfully!");
  },
  

  //FORGOT PASSWORD(SEND OTP)
  forgotPassword: async (req,res) => {
    const { email } = req.body;

    try {
      const user = await User.findOne({ email });
      if (!user) return res.status(400).send('User not found');

      const otp = generateOTP();
      user.otp = otp;
      user.otpExpires = Date.now();  // OTP expires in 10 mins
      const newUser = await user.save();

      // Send OTP via email
      await sendEmail(email, 'Password Reset OTP', `Your OTP is ${otp}`);

      res.status(200).json(newUser);
    } catch (error) {
      res.status(500).send('Server error');
    }
  },

  //RESET PASSWORD WITH OTP
  resetPassword: async (req, res) => {
    const { email,newPassword, otp } = req.body;

    try {
      const user = await User.findOne({email})
      if (user.otp !== otp) {
        return res.status(400).send('Invalid or expired OTP');
      }

      // Hash new password
      const hashedNewPassword = await bcrypt.hash(newPassword, 10);
      user.password = hashedNewPassword;

      // Clear OTP after successful password reset
      user.otp = null;
      user.otpExpires = null;
      const newUser = await user.save();

      res.status(200).json(newUser);
    } catch (error) {
      res.status(500).send('Server error');
    }
  },
};

module.exports = authController;
