require('dotenv').config();
const express = require('express');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const { body, validationResult } = require('express-validator');
const rateLimit = require('express-rate-limit');
const { Pool } = require('pg');

const app = express();
app.use(express.json());

// Create a connection pool to your PostgreSQL database.
const pool = new Pool({
  connectionString: process.env.DATABASE_URL || 'postgres://postgres:AJKajk@257@localhost:5432/linktrdb'
});

// JWT secret – in production, store this securely as an environment variable.
const JWT_SECRET = 'your_jwt_secret';

// Rate limiting middleware to prevent abuse.
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 100
});
app.use(limiter);

// Helper function to generate a referral code.
// We use the new user’s id plus a random string.
const generateReferralCode = (userId) => `REF-${userId}-${Math.random().toString(36).substr(2, 5)}`;

// Middleware to authenticate requests using JWT.
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  // Expect header format: "Bearer <token>"
  const token = authHeader && authHeader.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'Access token required' });

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) return res.status(403).json({ error: 'Invalid token' });
    req.user = user;
    next();
  });
};

/**
 * POST /api/register
 * Registers a new user.
 * Expects: { email, username, password, referralCode (optional) }
 */
app.post(
  '/api/register',
  [
    body('email').isEmail(),
    body('username').isLength({ min: 3 }),
    body('password').isLength({ min: 6 })
  ],
  async (req, res) => {
    // Validate input
    const errors = validationResult(req);
    if (!errors.isEmpty()) return res.status(400).json({ errors: errors.array() });

    const { email, username, password, referralCode } = req.body;

    try {
      // Check if email or username already exists.
      const existingUser = await pool.query(
        'SELECT id FROM users WHERE email = $1 OR username = $2',
        [email, username]
      );
      if (existingUser.rows.length > 0) {
        return res.status(400).json({ error: 'Email or username already in use' });
      }

      // Prepare for referral if a referral code is provided.
      let referredBy = null;
      if (referralCode) {
        const referrerResult = await pool.query(
          'SELECT id FROM users WHERE referral_code = $1',
          [referralCode]
        );
        if (referrerResult.rows.length === 0) {
          return res.status(400).json({ error: 'Invalid referral code' });
        }
        referredBy = referrerResult.rows[0].id;
      }

      // Hash the password.
      const hashedPassword = await bcrypt.hash(password, 10);

      // Insert the new user (without referral_code initially).
      const insertResult = await pool.query(
        `INSERT INTO users(email, username, password_hash, referred_by)
         VALUES ($1, $2, $3, $4) RETURNING id`,
        [email, username, hashedPassword, referredBy]
      );
      const newUserId = insertResult.rows[0].id;

      // Generate a referral code and update the user record.
      const newReferralCode = generateReferralCode(newUserId);
      await pool.query(
        'UPDATE users SET referral_code = $1 WHERE id = $2',
        [newReferralCode, newUserId]
      );

      // Record the referral if applicable.
      if (referredBy) {
        await pool.query(
          `INSERT INTO referrals(referrer_id, referred_user_id, status)
           VALUES ($1, $2, 'successful')`,
          [referredBy, newUserId]
        );
      }

      res.status(201).json({ message: 'User registered successfully', userId: newUserId });
    } catch (err) {
      console.error(err);
      res.status(500).json({ error: 'Server error' });
    }
  }
);

/**
 * POST /api/login
 * Authenticates a user and returns a JWT token.
 * Expects: { email, password }
 */
app.post('/api/login', async (req, res) => {
  const { email, password } = req.body;

  try {
    // Retrieve the user by email.
    const userResult = await pool.query(
      'SELECT * FROM users WHERE email = $1',
      [email]
    );
    if (userResult.rows.length === 0) {
      return res.status(400).json({ error: 'Invalid credentials' });
    }
    const user = userResult.rows[0];

    // Verify the password.
    const isMatch = await bcrypt.compare(password, user.password_hash);
    if (!isMatch) return res.status(400).json({ error: 'Invalid credentials' });

    // Generate a JWT token.
    const token = jwt.sign({ id: user.id, email: user.email }, JWT_SECRET, { expiresIn: '1h' });
    res.json({ message: 'Login successful', token });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Server error' });
  }
});

/**
 * POST /api/forgot-password
 * Initiates password reset by generating a reset token.
 * Expects: { email }
 * (In production, send the token via email.)
 */
app.post(
  '/api/forgot-password',
  [body('email').isEmail()],
  async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) return res.status(400).json({ errors: errors.array() });

    const { email } = req.body;

    try {
      const userResult = await pool.query(
        'SELECT * FROM users WHERE email = $1',
        [email]
      );
      if (userResult.rows.length === 0) {
        return res.status(400).json({ error: 'Email not found' });
      }
      const user = userResult.rows[0];

      // Create a reset token valid for 1 hour.
      const resetToken = jwt.sign({ id: user.id, email: user.email }, JWT_SECRET, { expiresIn: '1h' });

      // In a real implementation, save the token in a dedicated table or send it via email.
      // Here we simply return it.
      res.json({ message: 'Password reset token generated', resetToken });
    } catch (err) {
      console.error(err);
      res.status(500).json({ error: 'Server error' });
    }
  }
);

/**
 * POST /api/reset-password
 * Resets the user password given a valid reset token.
 * Expects: { email, resetToken, newPassword }
 */
app.post(
  '/api/reset-password',
  [
    body('email').isEmail(),
    body('resetToken').notEmpty(),
    body('newPassword').isLength({ min: 6 })
  ],
  async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) return res.status(400).json({ errors: errors.array() });

    const { email, resetToken, newPassword } = req.body;

    try {
      // Verify the reset token.
      jwt.verify(resetToken, JWT_SECRET);

      // Retrieve the user.
      const userResult = await pool.query(
        'SELECT * FROM users WHERE email = $1',
        [email]
      );
      if (userResult.rows.length === 0) return res.status(400).json({ error: 'User not found' });

      // Update the password.
      const newHashedPassword = await bcrypt.hash(newPassword, 10);
      await pool.query(
        'UPDATE users SET password_hash = $1 WHERE email = $2',
        [newHashedPassword, email]
      );

      res.json({ message: 'Password has been reset successfully' });
    } catch (err) {
      console.error(err);
      return res.status(400).json({ error: 'Invalid or expired reset token' });
    }
  }
);

/**
 * GET /api/referrals
 * Retrieves a list of users that were referred by the authenticated user.
 * Requires JWT authentication.
 */
app.get('/api/referrals', authenticateToken, async (req, res) => {
  const userId = req.user.id;

  try {
    const referralsResult = await pool.query(
      'SELECT * FROM referrals WHERE referrer_id = $1',
      [userId]
    );
    res.json({ referrals: referralsResult.rows });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Server error' });
  }
});

/**
 * GET /api/referral-stats
 * Returns statistics about the referral system for the authenticated user.
 * Requires JWT authentication.
 */
app.get('/api/referral-stats', authenticateToken, async (req, res) => {
  const userId = req.user.id;

  try {
    const statsResult = await pool.query(
      `SELECT COUNT(*) AS successful_referrals 
       FROM referrals 
       WHERE referrer_id = $1 AND status = 'successful'`,
      [userId]
    );
    res.json({ successfulReferrals: statsResult.rows[0].successful_referrals });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Server error' });
  }
});

// Global error handler.
app.use((err, req, res, next) => {
  console.error(err.stack);
  res.status(500).json({ error: 'Something went wrong!' });
});

// Start the server.
const PORT = process.env.PORT || 3000;
if (require.main === module) {
  app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
  });
} else {
  module.exports = app;
}
