require('dotenv').config(); // Load environment variables
const http = require('http');
const express = require('express');
const cookieParser = require('cookie-parser');
const path = require('path');
const routes = require('./routes'); // Import routes.js
const swagger = require('./swagger'); // Swagger setup
const cors = require("cors");


// Initialize Express app
const app = express();

// Middleware Setup
app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());

// Swagger Documentation
swagger(app);

// API Routes (defined in routes.js)
app.use('/routes/routes', routes);

// Error Handling Middleware
app.use((err, req, res, next) => {
    console.error(err.stack); // Log error stack trace
    res.status(500).json({ message: 'Something went wrong!', error: err.message });
});

// Start the Server
const port = process.env.PORT || 83;
http.createServer(app).listen(port, () => {
    console.log(`Server running at http://localhost:${port}/`);
});