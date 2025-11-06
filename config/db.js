'use strict';

const mongoose = require('mongoose');

async function wait(ms) {
    return new Promise((resolve) => setTimeout(resolve, ms));
}

async function connectDB(maxRetries = 5) {
    const uri = process.env.MONGO_URI;

    if (!uri) {
        console.error('[DB] MONGO_URI not set');
        throw new Error('MONGO_URI not set');
    }

    let attempt = 0;

    while (attempt <= maxRetries) {
        try {
            attempt += 1;
            console.log(`[DB] Connecting to MongoDB (attempt ${attempt})...`);
            await mongoose.connect(uri);
            console.log('[DB] MongoDB connected');
            
            return mongoose.connection;
        } catch (err) {
            console.error(`[DB] Connection failed (attempt ${attempt}):`, err.message);

            if (attempt > maxRetries) {
                console.error('[DB] Out of retries, giving up.');
                throw err;
            }
            
            const backoffMs = Math.min(30000, 1000 * Math.pow(2, attempt - 1));
            console.log(`[DB] Retrying in ${backoffMs}ms...`);
            await wait(backoffMs);
        }
    }
}

module.exports = { connectDB };
