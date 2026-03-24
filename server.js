const express = require('express');
const { auth } = require('express-oauth2-jwt-bearer');
require('dotenv').config();

const app = express();
app.use(express.json());

// 1. JWT Validation Middleware (Replaces API Gateway Cognito Authorizer)
const checkJwt = auth({
  audience: process.env.AUTH0_AUDIENCE,
  issuerBaseURL: `https://${process.env.AUTH0_DOMAIN}/`,
});

// 2. RBAC Middleware (Replaces IAM Policies)
const checkRole = (requiredRole) => (req, res, next) => {
  const namespace = 'https://mycloudassignment.com/roles';
  const userRoles = req.auth.payload[namespace] || [];

  if (userRoles.includes(requiredRole)) {
    next();
  } else {
    console.warn(`[UNAUTHORIZED] User attempted to access ${req.path} without ${requiredRole} role.`);
    res.status(403).json({ error: 'Forbidden: You do not have the required IAM role.' });
  }
};

// --- ROUTES ---

// Public Route (No token required)
app.get('/api/public', (req, res) => {
  console.log('[SUCCESS] Public route accessed.');
  res.json({ message: 'Hello from a public endpoint! You do not need to be authenticated to see this.' });
});

// Protected Route (Requires ANY valid JWT)
app.get('/api/private', checkJwt, (req, res) => {
  console.log('[SUCCESS] Private route accessed by valid token.');
  res.json({ message: 'Valid token accepted! You are authenticated.' });
});

// Admin Route (Requires valid JWT AND Admin role)
app.get('/api/admin', checkJwt, checkRole('Admin'), (req, res) => {
  console.log('[SUCCESS] Admin route accessed by an authorized Admin.');
  res.json({ message: 'Welcome Admin! You have access to restricted resources.' });
});

// --- ERROR HANDLING & MONITORING ---

// Catch-all for authentication errors (invalid token, expired token, no token)
app.use((err, req, res, next) => {
  if (err.name === 'UnauthorizedError' || err.status === 401) {
    console.error(`[SECURITY EVENT] Failed access attempt on ${req.path}. Reason: ${err.message}`);
    return res.status(401).json({ error: 'Unauthorized: Invalid, expired, or missing token.' });
  }
  next(err);
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});