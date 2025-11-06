'use strict';

const mongoose = require('mongoose');

const transactionSchema = new mongoose.Schema({
        senderId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
        receiverId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
        amount: { type: mongoose.Schema.Types.Decimal128, required: true, min: '0.01' },
    },
    { timestamps: true }
);

module.exports = mongoose.model('Transaction', transactionSchema);
