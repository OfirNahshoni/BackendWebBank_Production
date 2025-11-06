'use strict';

const express = require('express');
const mongoose = require('mongoose');
const User = require('../models/User');
const Transaction = require('../models/Transaction');
const router = express.Router();

function toDecimal128String(d) {
    // first value of balance is 500.00
    if (!d) {
        return '500.00';
    }

    try {
        // mongoose's toString()
        return d.toString();
    } catch (_e) {
        return String(d);
    }
}

// GET /balance
router.get('/balance', async (req, res, next) => {
    try {
        const userId = req.user && req.user.userId;

        if (!userId) {
            return res.status(401).json({ error: 'Unauthorized - userId not found' });
        }
        
        const user = await User.findById(userId).lean();
        
        if (!user) {
            return res.status(401).json({ error: 'Unauthorized - user not found' });
        }
        
        return res.json({ balance: toDecimal128String(user.balance) });
    } catch (err) {
        return next(err);
    }
});

// POST /transactions
router.post('/transactions', async (req, res, next) => {
    const session = await mongoose.startSession();
    try {
        const { recipientEmail, amount } = req.body || {};
        const senderId = req.user && req.user.userId;

        if (!senderId) {
            return res.status(401).json({ error: 'Unauthorized' });
        }
        
        const amt = Number(amount);

        if (!recipientEmail || !/.+@.+\..+/.test(recipientEmail) || !isFinite(amt) || amt <= 0) {
            return res.status(400).json({ error: 'Invalid request body' });
        }

        await session.withTransaction(async () => {
            const sender = await User.findById(senderId).session(session);
            
            if (!sender) {
                throw Object.assign(new Error('Sender not found'), { status: 400 });
            }

            const recipient = await User.findOne({ email: recipientEmail.toLowerCase() }).session(session);
            
            if (!recipient) {
                throw Object.assign(new Error('Recipient not found'), { status: 400 });
            }

            const senderBal = parseFloat(sender.balance ? sender.balance.toString() : '0');

            if (senderBal < amt) {
                throw Object.assign(new Error('Insufficient balance'), { status: 400 });
            }

            const newSenderBal = (senderBal - amt).toFixed(2);
            const recipientBal = parseFloat(recipient.balance ? recipient.balance.toString() : '0');
            const newRecipientBal = (recipientBal + amt).toFixed(2);

            sender.balance = mongoose.Types.Decimal128.fromString(String(newSenderBal));
            recipient.balance = mongoose.Types.Decimal128.fromString(String(newRecipientBal));

            await sender.save({ session });
            await recipient.save({ session });
            await Transaction.create([
            {
                senderId: sender._id,
                receiverId: recipient._id,
                amount: mongoose.Types.Decimal128.fromString(String(amt.toFixed(2))),
            },
            ], { session });
        });

        return res.json({ message: 'Transfer successful' });
    } catch (err) {
        if (session.inTransaction()) {
            await session.abortTransaction();
        }

        const status = err.status || 500;

        return res.status(status).json({ error: err.message || 'Transfer failed' });
    } finally {
        session.endSession();
    }
});

// POST /update-balance
router.post('/update-balance', async (req, res, next) => {
    try {
        const { amount } = req.body || {};
        const userId = req.user && req.user.userId;

        if (!userId) {
            return res.status(401).json({ error: 'Unauthorized - userId not found' });
        }
        
        const delta = Number(amount);
        
        if (!isFinite(delta)) {
            return res.status(400).json({ error: 'Invalid amount' });
        }

        const user = await User.findById(userId);

        if (!user) {
            return res.status(401).json({ error: 'Unauthorized - user not found' });
        }

        const current = parseFloat(user.balance ? user.balance.toString() : '0');
        const newBalance = (current + delta);
        user.balance = mongoose.Types.Decimal128.fromString(String(newBalance.toFixed(3)));
        await user.save();

        return res.json({ message: 'Balance updated', newBalance: toDecimal128String(user.balance) });
    } catch (err) {
        return next(err);
    }
});

module.exports = router;
