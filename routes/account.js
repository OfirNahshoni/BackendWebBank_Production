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

router.get('/transactions', async (req, res, next) => {
    try {
        const userId = req.user && req.user.userId;

        if (!userId) {
            return res.status(401).json({ error: 'Unauthorized - userId not found' });
        }

        const page = Math.max(parseInt(req.query.page, 5) || 1, 1);
        const limit = Math.min(Math.max(parseInt(req.query.limit, 10) || 10, 1), 100);
        const skip = (page - 1) * limit;

        // filter transactions - user is either sender or receiver
        const filter = { $or: [{ senderId: userId }, { receiverId: userId}] };

        // get transactions & filter by date (new -> old)
        const [docs, total] = await Promise.all([
            Transaction.find(filter).sort({ createdAt: -1 }).skip(skip).limit(limit).lean(),
            Transaction.countDocuments(filter),
        ]);

        // preload sender & receiver user data
        const neededIds = new Set(
            docs.map(d => String(d.senderId) === String(userId) ? 
                    String(d.receiverId) : 
                    String(d.senderId))
        );
        const users = await User.find({ _id: { $in: Array.from(neededIds) } });
        const emailById = new Map(users.map(u => [String(u._id), u.email]));

        // normalize transaction data
        const items = docs.map(d => {
            const isOut = String(d.senderId) === String(userId);
            const cpId = isOut ? d.receiverId : d.senderId;
            return {
                id: String(d._id),
                createdAt: d.createdAt,
                type: isOut ? 'out' : 'in',
                amount: d.amount ? d.amount.toString() : '0.00',
                counterpatryEmail: emailById.get(String(cpId)) || null,
            };
        });

        return res.json({ items, page, limit, total, hasNextPage: skip + limit < total });
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
