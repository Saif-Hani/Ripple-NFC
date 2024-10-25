const express = require('express');
const session = require('express-session');
const bcrypt = require('bcrypt');
const db = require('./database'); // SQLite connection from database.js

const app = express();
const PORT = 3000;

app.set('view engine', 'ejs'); // Set EJS as the template engine
app.set('views', './views'); // Create a 'views' folder for EJS templates


// Middleware to serve static files and parse form data
app.use(express.static('public'));
app.use(express.urlencoded({ extended: true }));

// Session middleware setup
app.use(
  session({
    secret: 'mysecretkey',
    resave: false,
    saveUninitialized: false,
    cookie: { maxAge: 3600000 }, // 1-hour session expiration
  })
);

// Route: Homepage with optional error handling
app.get('/', (req, res) => {
  const error = req.query.error;
  if (req.session.username) {
    return res.redirect('/profile');
  }
  res.sendFile(__dirname + '/index.html');
});

// Route: Signup with bcrypt password hashing
app.post('/signup', (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) {
    return res.redirect('/?error=empty');
  }

  bcrypt.hash(password, 10, (err, hash) => {
    if (err) return res.redirect('/?error=signup_error');
    db.run(
      `INSERT INTO users (username, password) VALUES (?, ?)`,
      [username, hash],
      (err) => {
        if (err) return res.redirect('/?error=exists');
        res.redirect('/');
      }
    );
  });
});

// Route: Login with bcrypt password comparison
app.post('/login', (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) {
    return res.redirect('/?error=empty');
  }

  db.get(`SELECT * FROM users WHERE username = ?`, [username], (err, user) => {
    if (err || !user) return res.redirect('/?error=invalid');

    bcrypt.compare(password, user.password, (err, result) => {
      if (result) {
        req.session.username = user.username;
        res.redirect('/profile');
      } else {
        res.redirect('/?error=invalid');
      }
    });
  });
}); 

// Route: Profile page with profile editing
app.get('/profile', (req, res) => {
  if (req.session.username) {
    res.sendFile(__dirname + '/public/profile.html');
  } else {
    res.redirect('/'); // Redirect to homepage if not logged in`
  }
});


// Route: Profile update with new credentials
app.post('/update', (req, res) => {
  const { newUsername, newPassword } = req.body;
  const username = req.session.username;

  bcrypt.hash(newPassword, 10, (err, hash) => {
    if (err) return res.redirect('/profile?error=update_error');
    db.run(
      `UPDATE users SET username = ?, password = ? WHERE username = ?`,
      [newUsername, hash, username],
      (err) => {
        if (err) return res.redirect('/profile?error=update_error');
        req.session.username = newUsername;
        res.redirect('/profile');
      }
    );
  });
});

// Route: Logout and destroy session
app.get('/logout', (req, res) => {
  req.session.destroy((err) => {
    if (err) return res.send('Error logging out.');
    res.redirect('/');
  });
});

// Route: Password reset (Optional)
app.post('/reset-password', (req, res) => {
  const { username } = req.body;
  const newPassword = 'newpassword123'; // Example new password

  bcrypt.hash(newPassword, 10, (err, hash) => {
    if (err) return res.send('Error resetting password.');
    db.run(
      `UPDATE users SET password = ? WHERE username = ?`,
      [hash, username],
      (err) => {
        if (err) return res.send('User not found.');
        res.send(`Password reset successful! New password: ${newPassword}`);
      }
    );
  });
});

// Start the server
app.listen(PORT, () => {
  console.log(`Server running on http://localhost:${PORT}`);
});
