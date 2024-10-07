const express = require('express');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const bodyParser = require('body-parser');
const mysql = require('mysql2');

// Create Express App
const app = express();
app.use(bodyParser.json());

// Create MySQL Database Connection
const db = mysql.createConnection({
  host: 'localhost',
  user: 'root',       // Use your database user
  password: '',       // Your password
  database: 'tugastreetbets' // Your database
});

db.connect((err) => {
  if (err) throw err;
  console.log('Database Connected...');
});

// Register User
app.post('/register', async (req, res) => {
  const { username, password } = req.body;

  // Check if user already exists
  const userCheckQuery = 'SELECT * FROM users WHERE username = ?';
  db.query(userCheckQuery, [username], async (error, results) => {
    if (results.length > 0) {
      return res.status(400).send('User already exists');
    }

    // Hash the password before saving
    const hashedPassword = await bcrypt.hash(password, 10);

    const insertQuery = 'INSERT INTO users (username, password) VALUES (?, ?)';
    db.query(insertQuery, [username, hashedPassword], (err, result) => {
      if (err) throw err;
      res.status(201).send('User created');
    });
  });
});

// Login User
app.post('/login', (req, res) => {
  const { username, password } = req.body;

  const findUserQuery = 'SELECT * FROM users WHERE username = ?';
  db.query(findUserQuery, [username], async (error, results) => {
    if (results.length === 0) {
      return res.status(400).send('User not found');
    }

    const user = results[0];
    
    // Compare hashed password
    const validPassword = await bcrypt.compare(password, user.password);
    if (!validPassword) {
      return res.status(400).send('Invalid credentials');
    }

    // Generate JWT (JSON Web Token) for session
    const token = jwt.sign({ id: user.id }, 'secretKey');
    res.status(200).json({ token });
  });
});

// Start Server
app.listen(3000, () => {
  console.log('Server started on port 3000');
});
