// backend/middleware/authMiddleware.js

'use strict';

const jwt = require('jsonwebtoken');

function extractToken(req) {
  const authHeader = req.headers && req.headers.authorization;

  if (!authHeader || typeof authHeader !== 'string') {
    return null;
  }
  
  const parts = authHeader.split(' ');

  if (parts.length !== 2) {
    return null;
  }
  
  const [scheme, token] = parts;

  if (!/^Bearer$/i.test(scheme)) {
    return null;
  }

  return token;
}

function verifyToken(token) {
  const secret = process.env.JWT_ACCESS_SECRET;

  if (!secret) {
    throw Object.assign(new Error('JWT secret not configured'), { status: 500 });
  }
  
  return jwt.verify(token, secret);
}

function requireAuth(req, res, next) {
  try {
    const token = extractToken(req);
    
    if (!token) {
      return res.status(401).json({ error: 'Unauthorized - token not found' });
    }
    const payload = verifyToken(token);
    req.user = { userId: payload.userId, email: payload.email };
    
    return next();
  } catch (err) {
    return res.status(401).json({ error: 'Unauthorized' });
  }
}

function optionalAuth(req, res, next) {
  try {
    const token = extractToken(req);

    if (!token) {
      req.user = null;

      return next();
    }
    
    const payload = verifyToken(token);
    req.user = { userId: payload.userId, email: payload.email };

    return next();
  } catch (_err) {
    req.user = null;

    return next();
  }
}

module.exports = { requireAuth, optionalAuth };
