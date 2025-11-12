'use strict';

const express = require('express');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const twilio = require('twilio');
const mongoose = require('mongoose');
const User = require('../models/User');

const router = express.Router();

function isValidEmail(email) {
    return typeof email === 'string' && /.+@.+\..+/.test(email);
}

function isNonEmptyString(s) {
    return typeof s === 'string' && s.trim().length > 0;
}

function genPin() {
    return String(Math.floor(100000 + Math.random() * 900000));
}

// add signature & expiration time to activation token
function signActivationToken(payload) {
    const secret = process.env.JWT_ACCESS_SECRET;

    if (!secret) {
        throw new Error('JWT secret not configured');
    }

    return jwt.sign(payload, secret, { expiresIn: '30m' });
}

// add signature & expiration time to login token
function signAccessToken(payload) {
    const secret = process.env.JWT_ACCESS_SECRET;

    if (!secret) {
        throw new Error('JWT secret not configured');
    }
    
    return jwt.sign(payload, secret, { expiresIn: '2h' });
}

/**
 * Send activation SMS using Twilio
 * 
 * Twilio is a cloud communications platform that provides APIs for sending SMS, 
 * making phone calls, and other communication services. It uses HTTPS REST APIs, 
 * so it works perfectly on Render (no port blocking issues).
 * 
 * How it works:
 * 1. You create a Twilio account and get credentials (Account SID, Auth Token)
 * 2. You get a phone number from Twilio (or use a trial number for testing)
 * 3. You use the Twilio SDK to send SMS via their API
 * 
 * @param {string} phoneNumber - The user's phone number (e.g., "0523134556" or "+972523134556")
 * @param {string} activationUrl - The full activation URL to send in the SMS
 * @returns {Promise} - Twilio message object
 */
async function sendActivationSMS(phoneNumber, activationUrl) {
    // Get Twilio credentials from environment variables
    const accountSid = process.env.TWILIO_ACCOUNT_SID;
    const authToken = process.env.TWILIO_AUTH_TOKEN;
    const fromNumber = process.env.TWILIO_PHONE_NUMBER;

    // Validate that all required credentials are present
    if (!accountSid || !authToken || !fromNumber) {
        throw new Error('Twilio credentials not configured. Please set TWILIO_ACCOUNT_SID, TWILIO_AUTH_TOKEN, and TWILIO_PHONE_NUMBER in your environment variables.');
    }

    // Initialize Twilio client with credentials
    // The client handles all API communication with Twilio's servers
    const client = twilio(accountSid, authToken);
    
    // Format phone number to international format (required by Twilio)
    // Twilio requires phone numbers in E.164 format: +[country code][number]
    // Example: +972523134556 (Israel) or +1234567890 (US)
    let formattedPhone = phoneNumber.trim();
    
    // If phone doesn't start with +, we need to add country code
    // For Israeli numbers starting with 0, replace 0 with +972
    if (formattedPhone.startsWith('0')) {
        formattedPhone = '+972' + formattedPhone.substring(1);
    } else if (!formattedPhone.startsWith('+')) {
        // If no country code, assume it's missing and add + (you may need to adjust this based on your country)
        formattedPhone = '+' + formattedPhone;
    }
    
    // Send SMS via Twilio API
    // This makes an HTTPS request to Twilio's servers - no port blocking!
    const message = await client.messages.create({
        body: `Activate your account: ${activationUrl}`,
        from: fromNumber,  // Your Twilio phone number
        to: formattedPhone // Recipient's phone number
    });

    // Return the message object (contains message SID, status, etc.)
    return message;
}

// POST /signup
// router.post('/signup', async (req, res, next) => {
//   try {
//     const { email, password, phone } = req.body || {};
    
//     if (!isValidEmail(email) || !isNonEmptyString(password) || !isNonEmptyString(phone)) {
//         return res.status(400).json({ error: 'Invalid request body' });
//     }

//     const existing = await User.findOne({ email: email.toLowerCase() }).lean();

//     if (existing) {
//         return res.status(400).json({ error: 'Email already registered' });
//     }

//     const passwordHash = await bcrypt.hash(password, 10);
//     const pin = genPin();
//     const pinHash = await bcrypt.hash(pin, 10);
//     const expiresAt = new Date(Date.now() + 30 * 60 * 1000);
//     const nonce = new mongoose.Types.ObjectId().toString();
//     const activationJWT = signActivationToken({ email: email.toLowerCase(), nonce });

//     // create user in db
//     const user = await User.create({
//         email: email.toLowerCase(),
//         phoneNumber: phone,
//         password: passwordHash,
//         status: 'inactive',
//         balance: mongoose.Types.Decimal128.fromString('500.000'),
//         emailVerificationPinHash: pinHash,
//         emailVerificationExpiresAt: expiresAt,
//     });

//     await user.save();

//     const appBase = process.env.BACK_BASE_URL;
//     const activationUrl = `${appBase}/api/v1/auth/${pin}/${activationJWT}`;

//     // sending mail to activate account
//     // try {
//         console.log('before create transport');
//         const transporter = createTransport();
//         console.log('after create transport');
        
//         if (transporter) {
//             await transporter.sendMail({
//                 from: process.env.SMTP_USER,
//                 to: user.email,
//                 subject: 'Activate your account',
//                 text: `Press the link to activate your account : ${activationUrl}`,
//             });
            
//             console.log('email sent to: ', user.email);
//         }
//     // } catch (_mailErr) {
//         // console.log('error sending mail: ', _mailErr);
//     // }

//     return res.status(201).json({ message: 'User registered successfully' });
// //   } catch (err) {
//     // return next(err);
// //   }
// });

router.post('/signup', async (req, res, next) => {
  const { email, password, phone } = req.body || {};
  
  if (!isValidEmail(email) || !isNonEmptyString(password) || !isNonEmptyString(phone)) {
      return res.status(400).json({ error: 'Invalid request body' });
  }

  const existing = await User.findOne({ email: email.toLowerCase() }).lean();

  if (existing) {
      return res.status(400).json({ error: 'Email already registered' });
  }

  const passwordHash = await bcrypt.hash(password, 10);
  const pin = genPin();
  const pinHash = await bcrypt.hash(pin, 10);
  const expiresAt = new Date(Date.now() + 30 * 60 * 1000);
  const nonce = new mongoose.Types.ObjectId().toString();
  const activationJWT = signActivationToken({ email: email.toLowerCase(), nonce });

  const user = await User.create({
      email: email.toLowerCase(),
      phoneNumber: phone,
      password: passwordHash,
      status: 'inactive',
      balance: mongoose.Types.Decimal128.fromString('500.000'),
      emailVerificationPinHash: pinHash,
      emailVerificationExpiresAt: expiresAt,
  });

  const appBase = process.env.BACK_BASE_URL;
  const activationUrl = `${appBase}/api/v1/auth/${pin}/${activationJWT}`;

  // Send activation SMS instead of email
  try {
      console.log('Sending activation SMS to:', phone);
      const smsResult = await sendActivationSMS(phone, activationUrl);
      console.log('SMS sent successfully. Message SID:', smsResult.sid);
  } catch (smsErr) {
      console.error('Error sending SMS:', smsErr.message);
      // Don't throw - we still want to return success since user was created
      // The user can request a new activation link if needed
  }

  return res.status(201).json({ message: 'User registered successfully' });
});

// PUT /auth/:pincode/:JWT
router.get('/auth/:pincode/:JWT', async (req, res, next) => {
    try {
        const pin = req.params.pincode;
        const token = req.params.JWT;
        
        if (!isNonEmptyString(pin) || !isNonEmptyString(token)) {
            return res.status(400).json({ error: 'Invalid activation data - pin or jwt missing' });
        }
        
        const secret = process.env.JWT_ACCESS_SECRET;
        
        if (!secret) {
            return res.status(500).json({ error: 'Server misconfigured - secret jwt missing' });
        }

        let decoded;

        try {
            decoded = jwt.verify(token, secret);
        } catch (_e) {
            return res.status(400).json({ error: 'Invalid or expired token' });
        }

        const email = decoded && decoded.email;

        if (!isValidEmail(email)) {
            return res.status(400).json({ error: 'Invalid token payload' });
        }

        const user = await User.findOne({ email: email.toLowerCase() });
        
        if (!user) {
            return res.status(400).json({ error: 'User not found' });
        }

        if (!user.emailVerificationPinHash || !user.emailVerificationExpiresAt) {
            return res.status(400).json({ error: 'Activation not initialized' });
        }
        if (user.emailVerificationExpiresAt.getTime() < Date.now()) {
            return res.status(400).json({ error: 'PIN expired' });
        }
        const ok = await bcrypt.compare(pin, user.emailVerificationPinHash);

        if (!ok) {
            return res.status(400).json({ error: 'Invalid PIN' });
        }

        user.status = 'active';
        user.emailVerificationPinHash = undefined;
        user.emailVerificationExpiresAt = undefined;
        await user.save();

        // for auto-login
        // const loginToken = signAccessToken({ userId: user._id.toString(), email: user.email });

        
        const frontBaseUrl = process.env.FRONT_BASE_URL || "http://localhost:5173";
        
        return res.redirect(301, `${frontBaseUrl}/login?activated=1`);
        
        // return res.json({ token: loginToken });
    } catch (err) {
        // On any failure, redirect with a reason (URL-encoded)
        const frontBaseUrl = process.env.FRONT_BASE_URL;
        const reason = encodeURIComponent(err && err.message ? err.message : 'Activation failed');

        return res.redirect(302, `${frontBaseUrl}/login?activated=0&reason=${reason}`);
    }
});

// POST /login
router.post('/login', async (req, res, next) => {
  try {
    const { email, password } = req.body || {};

    if (!isValidEmail(email) || !isNonEmptyString(password)) {
        return res.status(400).json({ error: 'Invalid request body' });
    }

    const user = await User.findOne({ email: email.toLowerCase() });
    
    if (!user) {
        return res.status(401).json({ error: 'Invalid credentials' });
    }

    if (user.status === 'inactive') {
        return res.status(401).json({ error: 'Account not activated' });
    }
    
    const ok = await bcrypt.compare(password, user.password);

    if (!ok) {
        return res.status(401).json({ error: 'Invalid credentials' });
    }

    const token = signAccessToken({ userId: user._id.toString(), email: user.email });

    return res.json({ message: 'User logged successfully', token });
  } catch (err) {
    return next(err);
  }
});

module.exports = router;
