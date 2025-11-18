'use strict';

const express = require('express');
const mongoose = require('mongoose');
const User = require('../models/User');
const Transaction = require('../models/Transaction');
const { decimal128ToNumber } = require('../utils/money');
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

router.get('/transactions', async (req, res, next) => {
    try {
        const userId = req.user && req.user.userId;

        if (!userId) {
            return res.status(401).json({ error: 'Unauthorized - userId not found' });
        }

        const { page = '1', pageSize = '5', type = 'out' } = req.query || {};
        const pageNumber = Number(page) || 1;
        const sizeNumber = Number(pageSize) || 5;
        const skip = (pageNumber - 1) * sizeNumber;
        const isOut = type === 'out';
        const filter = isOut ? { senderId: userId } : { receiverId: userId };

        const [docs, total] = await Promise.all([
            Transaction.find(filter)
                .sort({ createdAt: -1 })
                .skip(skip)
                .limit(sizeNumber)
                .lean(),
            Transaction.countDocuments(filter),
        ]);

        const counterpartIds = docs.map((doc) =>
            isOut ? doc.receiverId : doc.senderId
        );
        const users = await User.find({ _id: { $in: counterpartIds } }).lean();
        const emailById = new Map(users.map((user) => [String(user._id), user.email]));

        const items = docs.map((doc, index) => {
            const outbound = String(doc.senderId) === String(userId);
            const counterpartyId = outbound ? doc.receiverId : doc.senderId;
            return {
                id: String(doc._id),
                amount: decimal128ToNumber(doc.amount),
                otherMail: emailById.get(String(counterpartyId)) || null,
                date: doc.createdAt,
                row: skip + index + 1,
            };
        });

        const hasNextPage = skip + docs.length < total;
        const totalPages = Math.ceil(total / sizeNumber) || 0;

        return res.json({
            items,
            total,
            totalPages,
            page: pageNumber,
            pageSize: sizeNumber,
            hasNextPage,
        });
    } catch (err) {
        return next(err);
    }
});

// POST /transactions
router.post('/transactions', async (req, res, next) => {
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

        // Try transactions first, fallback to non-transactional if replica set not available
        try {
            const session = await mongoose.startSession();
            try {
                await session.withTransaction(async () => {
                    const sender = await User.findById(senderId).session(session);
                    
                    if (!sender) {
                        throw Object.assign(new Error('Sender not found'), { status: 400 });
                    }

                    if (sender.email.toLowerCase() == recipientEmail.toLowerCase()) {
                        throw Object.assign(new Error('You cannot send money to yourself'), { status: 400 });
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
                    
                    await Transaction.create([{
                        senderId: sender._id,
                        receiverId: recipient._id,
                        amount: mongoose.Types.Decimal128.fromString(String(amt.toFixed(2))),
                    }], { session });
                });
                return res.json({ message: 'Transfer successful' });
            } finally {
                session.endSession();
            }
        } catch (transactionError) {
            // If transaction error (e.g., replica set required), fallback to non-transactional
            const errorMsg = transactionError.message || '';
            
            if (errorMsg.includes('replica set') || errorMsg.includes('Transaction numbers')) {
                // Fallback for standalone MongoDB (no transactions)
                const sender = await User.findById(senderId);

                if (!sender) {
                    return res.status(400).json({ error: 'Sender not found' });
                }

                if (sender.email.toLowerCase() == recipientEmail.toLowerCase()) {
                    throw Object.assign(new Error('You cannot send money to yourself'), { status: 400 });
                }
                
                const recipient = await User.findOne({ email: recipientEmail.toLowerCase() });
                
                if (!recipient) {
                    return res.status(400).json({ error: 'Recipient not found' });
                }
                
                const senderBal = parseFloat(sender.balance ? sender.balance.toString() : '0');
                
                if (senderBal < amt) {
                    return res.status(400).json({ error: 'Insufficient balance' });
                }
                
                const newSenderBal = (senderBal - amt).toFixed(2);
                const recipientBal = parseFloat(recipient.balance ? recipient.balance.toString() : '0');
                const newRecipientBal = (recipientBal + amt).toFixed(2);
                sender.balance = mongoose.Types.Decimal128.fromString(String(newSenderBal));
                recipient.balance = mongoose.Types.Decimal128.fromString(String(newRecipientBal));
                
                await sender.save();
                await recipient.save();

                await Transaction.create([{
                    senderId: sender._id,
                    receiverId: recipient._id,
                    amount: mongoose.Types.Decimal128.fromString(String(amt.toFixed(2))),
                }]);
                
                return res.json({ message: 'Transfer successful' });
            }
            // Re-throw if it's not a transaction error
            throw transactionError;
        }
    } catch (err) {
        const status = err.status || 500;
        return res.status(status).json({ error: err.message || 'Transfer failed' });
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

        const currentBalance = parseFloat(user.balance ? user.balance.toString() : '0');
        
        if (delta < 0 && Math.abs(delta) > currentBalance) {
            return res.status(400).json({ error: 'Insufficient balance' });
        }

        const newBalance = (currentBalance + delta);
        user.balance = mongoose.Types.Decimal128.fromString(String(newBalance.toFixed(3)));
        await user.save();

        return res.json({ message: 'Balance updated', newBalance: toDecimal128String(user.balance) });
    } catch (err) {
        return next(err);
    }
});

module.exports = router;
