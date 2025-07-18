const express = require('express');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const User = require('../models/User');
const router = express.Router();

// JWT secret
const jwtSecret = process.env.JWT_SECRET || 'amrish';

// Render login page
router.get('/login', (req, res) => {
    res.render('login');
});

// Render signup page
router.get('/signup', (req, res) => {
    res.render('signup');
});

// Handle signup
router.post('/signup', async (req, res) => {
    const { username, email, password } = req.body;

    try {
        let user = await User.findOne({ email });
        if (user) {
            return res.status(400).send('User already exists');
        }

        user = new User({
            username,
            email,
            password
        });

        await user.save();
        res.redirect('/auth/login');
    } catch (err) {
        console.error(err.message);
        res.status(500).send('Server error');
    }
});

// Handle login
router.post('/login', async (req, res) => {
    const { email, password } = req.body;

    try {
        const user = await User.findOne({ email });
        if (!user) {
            return res.status(400).send('Invalid credentials');
        }

        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) {
            return res.status(400).send('Invalid credentials');
        }

        const payload = { userId: user.id };
        const token = jwt.sign(payload, jwtSecret, { expiresIn: '1h' });
        res.cookie('token', token, { httpOnly: true });

        res.redirect('/auth/profile');
    } catch (err) {
        console.error(err.message);
        res.status(500).send('Server error');
    }
});

// Profile page (protected route)
router.get('/profile', verifyToken, (req, res) => {
    res.render('profile', { username: req.user.username });
});

// Middleware to verify JWT
function verifyToken(req, res, next) {
    const token = req.cookies.token;
    if (!token) {
        return res.redirect('/auth/login');
    }
    try {
        const decoded = jwt.verify(token, jwtSecret);
        req.user = decoded;
        next();
    } catch (err) {
        res.clearCookie('token');
        return res.redirect('/auth/login');
    }
}

module.exports = router;
