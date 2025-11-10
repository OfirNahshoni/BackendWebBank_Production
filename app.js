// backend/app.js

require('dotenv').config();
var express = require('express');
var path = require('path');
var morgan = require('morgan');
var helmet = require('helmet');
var cors = require('cors');
var mongoose = require('mongoose');

var { requireAuth } = require('./middleware/authMiddleware');
var authRouter = require('./routes/auth');
var accountRouter = require('./routes/account');

var app = express();

// Security & ops middleware
app.use(helmet());
app.use(cors());
app.use(morgan('dev'));
app.use(express.json());
app.use(express.urlencoded({ extended: false }));

// Static files
app.use(express.static(path.join(__dirname, 'public')));

// DB connection (basic)
if (process.env.MONGO_URI) {
    mongoose.connect(process.env.MONGO_URI).catch((err) => console.error('Mongo connection error:', err));
}

// API routes under /api/v1
app.use('/api/v1', authRouter);
app.use('/api/v1', requireAuth, accountRouter);

// Centralized error handler
app.use(function (err, req, res, next) {
    const status = err.status || 500;
    const payload = { error: err.message || 'Internal Server Error' };

    if (process.env.NODE_ENV !== 'production' && err.stack) {
        payload.details = err.stack;
    }

    res.status(status).json(payload);
});

module.exports = app;
