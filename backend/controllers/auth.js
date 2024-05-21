const User = require('../models/user');
const Profile = require('../models/profile');
const otpGenerator = require('otp-generator');
const OTP = require('../models/OTP');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
require('dotenv').config();
const cookie = require('cookie');
const mailSender = require('../utils/mailSender');
const otpTemplate = require('../mail/templates/emailVerificationTemplate');
const { passwordUpdated } = require("../mail/templates/passwordUpdate");

// ================ SEND-OTP For Email Verification ================
exports.sendOTP = async (req, res) => {
    try {
        const { email } = req.body;

        const checkUserPresent = await User.findOne({ email });

        if (checkUserPresent) {
            console.log('User already registered');
            return res.status(401).json({
                success: false,
                message: 'User is already registered'
            });
        }

        const otp = otpGenerator.generate(6, {
            upperCaseAlphabets: false,
            lowerCaseAlphabets: false,
            specialChars: false
        });

        const name = email.split('@')[0].split('.').map(part => part.replace(/\d+/g, '')).join(' ');

        await mailSender(email, 'OTP Verification Email', otpTemplate(otp, name));

        await OTP.create({ email, otp, createdAt: new Date() });

        res.status(200).json({
            success: true,
            message: 'OTP sent successfully'
        });
    } catch (error) {
        console.log('Error while generating OTP:', error);
        res.status(500).json({
            success: false,
            message: 'Error while generating OTP',
            error: error.message
        });
    }
}

// ================ SIGNUP ================
exports.signup = async (req, res) => {
    try {
        const { firstName, lastName, email, password, confirmPassword, accountType, contactNumber, otp } = req.body;

        if (!firstName || !lastName || !email || !password || !confirmPassword || !accountType || !otp) {
            return res.status(400).json({
                success: false,
                message: 'All fields are required'
            });
        }

        if (password !== confirmPassword) {
            return res.status(400).json({
                success: false,
                message: 'Password and confirm password do not match'
            });
        }

        const checkUserAlreadyExists = await User.findOne({ email });

        if (checkUserAlreadyExists) {
            return res.status(400).json({
                success: false,
                message: 'User already registered, please login'
            });
        }

        const recentOtp = await OTP.findOne({ email }).sort({ createdAt: -1 }).limit(1);

        if (!recentOtp || otp !== recentOtp.otp) {
            return res.status(400).json({
                success: false,
                message: 'Invalid or expired OTP'
            });
        }

        const hashedPassword = await bcrypt.hash(password, 10);

        const profileDetails = await Profile.create({
            gender: null, dateOfBirth: null, about: null, contactNumber: null
        });

        const approved = accountType === "Instructor" ? false : true;

        await User.create({
            firstName, lastName, email, password: hashedPassword, contactNumber,
            accountType, additionalDetails: profileDetails._id, approved,
            image: `https://api.dicebear.com/5.x/initials/svg?seed=${firstName} ${lastName}`
        });

        res.status(200).json({
            success: true,
            message: 'User registered successfully'
        });
    } catch (error) {
        console.log('Error while registering user:', error);
        res.status(500).json({
            success: false,
            message: 'User cannot be registered, please try again',
            error: error.message
        });
    }
}

// ================ LOGIN ================
exports.login = async (req, res) => {
    try {
        const { email, password } = req.body;

        if (!email || !password) {
            return res.status(400).json({
                success: false,
                message: 'All fields are required'
            });
        }

        let user = await User.findOne({ email }).populate('additionalDetails');

        if (!user) {
            return res.status(401).json({
                success: false,
                message: 'You are not registered with us'
            });
        }

        if (await bcrypt.compare(password, user.password)) {
            const payload = {
                email: user.email,
                id: user._id,
                accountType: user.accountType
            };

            const token = jwt.sign(payload, process.env.JWT_SECRET, {
                expiresIn: process.env.JWT_EXPIRE
            });

            user = user.toObject();
            user.token = token;
            user.password = undefined;

            const cookieOptions = {
                expires: new Date(Date.now() + 3 * 24 * 60 * 60 * 1000),
                httpOnly: true
            };

            res.cookie('token', token, cookieOptions).status(200).json({
                success: true,
                user,
                token,
                message: 'User logged in successfully'
            });
        } else {
            return res.status(401).json({
                success: false,
                message: 'Password does not match'
            });
        }
    } catch (error) {
        console.log('Error while logging in user:', error);
        res.status(500).json({
            success: false,
            message: 'Error while logging in user',
            error: error.message
        });
    }
}

// ================ CHANGE PASSWORD ================
exports.changePassword = async (req, res) => {
    try {
        const { oldPassword, newPassword, confirmNewPassword } = req.body;

        if (!oldPassword || !newPassword || !confirmNewPassword) {
            return res.status(400).json({
                success: false,
                message: 'All fields are required'
            });
        }

        const userDetails = await User.findById(req.user.id);

        const isPasswordMatch = await bcrypt.compare(oldPassword, userDetails.password);

        if (!isPasswordMatch) {
            return res.status(401).json({
                success: false,
                message: "Old password is incorrect"
            });
        }

        if (newPassword !== confirmNewPassword) {
            return res.status(400).json({
                success: false,
                message: 'The new password and confirm password do not match'
            });
        }

        const hashedPassword = await bcrypt.hash(newPassword, 10);

        const updatedUserDetails = await User.findByIdAndUpdate(req.user.id, { password: hashedPassword }, { new: true });

        try {
            await mailSender(
                updatedUserDetails.email,
                'Password Updated Successfully',
                passwordUpdated(updatedUserDetails.email, `Password updated successfully for ${updatedUserDetails.firstName} ${updatedUserDetails.lastName}`)
            );
        } catch (error) {
            console.error("Error while sending email:", error);
            return res.status(500).json({
                success: false,
                message: "Error while sending email",
                error: error.message
            });
        }

        res.status(200).json({
            success: true,
            message: 'Password changed successfully'
        });
    } catch (error) {
        console.log('Error while changing password:', error);
        res.status(500).json({
            success: false,
            message: 'Error while changing password',
            error: error.message
        });
    }
}
