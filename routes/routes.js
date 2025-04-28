const express = require('express');
const router = express.Router();
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const jwt = require('jsonwebtoken');
const passport = require('passport');
const JwtStrategy = require('passport-jwt').Strategy;
const ExtractJwt = require('passport-jwt').ExtractJwt;
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const {
    User,
    InsertUser,
} = require('../db/db'); // Import User model and InsertUser function

// Middleware to protect routes
async function auth(req, res, next) {
    const token = req.cookies.token;
    if (token) {
        try {
            const decoded = jwt.verify(token, process.env.JWT_SECRET);
            const user = await User.findById(decoded.user._id);
            if (!user) {
                return res.status(403).json({ msg: 'Token is not valid' });
            }
            req.user = user;
            next();
        } catch (err) {
            return res.status(403).json({ msg: 'Token is not valid' });
        }
    } else {
        res.status(401).json({ msg: 'Authorization cookie missing or invalid' });
    }
}

// JWT Strategy
const opts = {
    jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),
    secretOrKey: process.env.JWT_SECRET
};
passport.use(new JwtStrategy(opts, async(jwt_payload, done) => {
    try {
        const user = await User.findById(jwt_payload._id);
        if (user) {
            return done(null, user);
        } else {
            return done(null, false);
        }
    } catch (err) {
        return done(err, false);
    }
}));

// Google Strategy
passport.use(new GoogleStrategy({
    clientID: process.env.GOOGLE_CLIENT_ID,
    clientSecret: process.env.GOOGLE_CLIENT_SECRET,
    callbackURL: '/auth/google/callback',
    scope: ['profile', 'email', 'https://www.googleapis.com/auth/userinfo.profile']
}, async(accessToken, refreshToken, profile, done) => {
    try {
        console.log('Google profile:', profile); // Debugging statement
        let user = await User.findOne({ googleId: profile.id });
        if (!user) {
            const randomPassword = crypto.randomBytes(16).toString('hex');
            user = new User({
                googleId: profile.id,
                email: profile.emails[0].value,
                password: randomPassword,
                firstName: profile.name.givenName,
                lastName: profile.name.familyName
            });
            await user.save();
        } else {
            user.googleAccessToken = accessToken;
            user.googleRefreshToken = refreshToken;
            await user.save();
        }
        return done(null, user);
    } catch (err) {
        return done(err, false);
    }
}));


passport.serializeUser((user, done) => {
    done(null, user._id);
});

passport.deserializeUser(async(id, done) => {
    try {
        const user = await User.findById(id);
        done(null, user);
    } catch (err) {
        done(err, false);
    }
});

// Serve the favicon
router.get('/favicon.ico', (req, res) => {
    res.sendFile(path.join(__dirname, 'images', 'favicon.ico'));
});

// Serve the index page
router.get('/', (req, res) => {
    fs.readFile(path.join(__dirname, 'index.html'), (err, data) => {
        if (err) {
            res.writeHead(500, { 'Content-Type': 'text/html' });
            res.end("Error loading form");
        } else {
            res.writeHead(200, { 'Content-Type': 'text/html' });
            res.end(data);
        }
    });
});

// Serve the home page
router.get('/home', auth, (req, res) => {
    fs.readFile(path.join(__dirname, 'recipes.html'), (err, data) => {
        if (err) {
            res.writeHead(500, { 'Content-Type': 'text/html' });
            res.end("Error loading Page");
        } else {
            res.writeHead(200, { 'Content-Type': 'text/html' });
            res.end(data);
        }
    });
});


// Logout route
router.post('/logout', (req, res) => {
    res.clearCookie('token');
    res.json({ msg: 'Logged out successfully' });
});

// Serve Home Page
router.get('/home', (req, res) => {
    fs.readFile(path.join(__dirname, 'public/index.html'), (err, data) => {
        if (err) {
            res.writeHead(500, { 'Content-Type': 'text/html' });
            res.end("Error loading Page");
        } else {
            res.writeHead(200, { 'Content-Type': 'text/html' });
            res.end(data);
        }
    });
});

// Authentication Routes (Google/GitHub)
// Google Authentication
router.get('/auth/google', passport.authenticate('google', { scope: ['profile', 'email', 'https://www.googleapis.com/auth/userinfo.profile'] }));

router.get('/auth/google/callback', passport.authenticate('google', { session: false }), (req, res) => {
    const user = req.user;
    if (!user.gender) {
        // Redirect to a page where the user can enter their gender
        res.redirect(`/auth/complete-profile?userId=${user.id}`);
    } else {
        const payload = { user: { _id: user.id, firstName: user.firstName, lastName: user.lastName, gender: user.gender } };
        jwt.sign(payload, process.env.JWT_SECRET, { expiresIn: '1h' }, (err, token) => {
            if (err) {
                console.error('JWT sign error:', err); // Log the error
                return res.status(500).json({ message: 'Something went wrong!' });
            }
            res.cookie('token', token, { httpOnly: true });
            res.redirect('/home');
        });
    }
});
router.get('/auth/success', (req, res) => {
    const { token, userId, firstName, lastName, gender } = req.query; // Include gender in the query parameters
    const htmlContent = `
    <!DOCTYPE html>
    <html lang="en">
    <head>
      <meta charset="UTF-8">
      <meta name="viewport" content="width=device-width, initial-scale=1.0">
      <title>Authentication Success</title>
    </head>
    <body>
      <script>
        (function() {
          const token = "${token}";
          const userId = "${userId}";
          const firstName = "${firstName}";
          const lastName = "${lastName}";
          const gender = "${gender}"; // Include gender in the local storage
          if (token) {
            localStorage.setItem('token', token);
            localStorage.setItem('userId', userId);
            localStorage.setItem('firstName', firstName);
            localStorage.setItem('lastName', lastName);
            localStorage.setItem('gender', gender); // Save gender to local storage
            alert('Authentication successful!');
            window.location.href = '/home'; // Redirect to home page
          } else {
            alert('Authentication failed!');
            window.location.href = '/'; // Redirect to login page
          }
        })();
      </script>
    </body>
    </html>
    `;
    res.send(htmlContent);
});
router.get('/auth/complete-profile', (req, res) => {
    const { userId } = req.query;
    const htmlContent = `
    <!DOCTYPE html>
    <html lang="en">
    <head>
      <meta charset="UTF-8">
      <meta name="viewport" content="width=device-width, initial-scale=1.0">
      <title>Complete Profile</title>
    </head>
    <body>
      <form action="/auth/complete-profile" method="POST">
        <input type="hidden" name="userId" value="${userId}">
        <label for="gender">Gender:</label>
        <select name="gender" required>
          <option value="Male">Male</option>
          <option value="Female">Female</option>
          <option value="Other">Other</option>
        </select>
        <button type="submit">Submit</button>
      </form>
    </body>
    </html>
    `;
    res.send(htmlContent);
});

router.post('/auth/complete-profile', async(req, res) => {
    const { userId, gender } = req.body;
    try {
        const user = await User.findById(userId);
        if (!user) {
            return res.status(404).json({ msg: 'User not found' });
        }
        user.gender = gender;
        await user.save();
        const payload = { user: { _id: user.id, firstName: user.firstName, lastName: user.lastName, gender: user.gender } };
        jwt.sign(payload, process.env.JWT_SECRET, { expiresIn: '1h' }, (err, token) => {
            if (err) throw err;
            res.cookie('token', token, { httpOnly: true });
            res.redirect('/home');
        });
    } catch (err) {
        console.error('Error completing profile:', err);
        res.status(500).json({ msg: 'Error completing profile' });
    }
});


module.exports = router;