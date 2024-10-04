const express = require('express');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
require('dotenv').config();
const app = express();
app.use(express.json());
//simulate user database
const users = {};
app.get('/', (req, res) => {
    res.send('Welcome to the Cloud Security Application');
});
// Register
app.post('/register', async (req, res) => {
    const { username, password } = req.body;
    if (!username || !password) {
        return res.status(400).json({ msg: "Missing username or password" });
    }
    if (users[username]) {
        return res.status(400).json({ msg: "Username already exists" });
    }
    const hashedPassword = await bcrypt.hash(password, 10);
    users[username] = hashedPassword;
    res.status(201).json({ msg: "User registered successfully" });
});

// Login
app.post('/login', async (req, res) => {
    const { username, password } = req.body;
    if (!username || !password) {
        return res.status(400).json({ msg: "Missing username or password" });
    }
    const hashedPassword = users[username];
    
    if (!hashedPassword || !(await bcrypt.compare(password, hashedPassword))) {
        return res.status(401).json({ msg: "Bad username or password" });
    }
    const token = jwt.sign({ username }, process.env.JWT_SECRET, { expiresIn: '1h' });
    res.json({ access_token: token });
});

// authenticateToken for protected route, prevent unauthorized access
function authenticateToken(req, res, next) {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];
    if (token == null) return res.sendStatus(401);
// verify token
    jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
        if (err) return res.sendStatus(403);
        req.user = user;
        next();
    });
}

// Route được bảo vệ
app.get('/protected', authenticateToken, (req, res) => {
    res.json({ msg: "This is a protected route", user: req.user.username });
});
app.get('/users', (req, res) => {
    res.json(Object.keys(users));
});

const PORT = process.env.PORT || 5000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));