'use strict';

const mongoose = require('mongoose');

const userSchema = new mongoose.Schema({
        email: { type: String, required: true, unique: true, lowercase: true, trim: true },
        password: { type: String, required: true },
        phoneNumber: { type: String },
        balance: { type: mongoose.Schema.Types.Decimal128, default: '0.00' },
        status: { type: String, enum: ['active', 'inactive', 'blocked'], default: 'inactive' },
        emailVerificationPinHash: { type: String },
        emailVerificationExpiresAt: { type: Date },
    },
    { timestamps: true }
);

module.exports = mongoose.model('User', userSchema);
