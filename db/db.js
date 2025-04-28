const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const Joi = require('joi'); // For validation

// Get MongoDB URL from environment variables
const MONGOURL = process.env.MONGO_URL;

// Connect to MongoDB
mongoose.connect(MONGOURL, {})
    .then(() => {
        console.log('Connected to MongoDB');
    })
    .catch(err => {
        console.error('Error connecting to MongoDB:', err);
    });


// Define the User schema
const userSchema = new mongoose.Schema({
    email: { type: String, required: true, unique: true },
    password: { type: String, required: function() { return !this.googleId } },
    googleId: { type: String },
    firstName: { type: String },
    lastName: { type: String },
    gender: { type: String, enum: ['Male', 'Female', 'Other'], required: false } // Ensure gender is required
}); // Hash password before saving if it is provided
userSchema.pre('save', async function(next) {
    if (this.password && this.isModified('password')) {
        const salt = await bcrypt.genSalt(10);
        this.password = await bcrypt.hash(this.password, salt);
    }
    next();
});

// Create the models
const User = mongoose.model('User', userSchema);

// Validation schemas
const userValidationSchema = Joi.object({
    email: Joi.string().email().required(),
    password: Joi.string().min(6).required(),
    googleId: Joi.string().optional(),
    firstName: Joi.string().optional(),
    lastName: Joi.string().optional(),
    gender: Joi.string().valid('Male', 'Female', 'Other').required() // Ensure gender validation
});

// Function to insert a new user
const insertUser = async(email, password) => {
    try {
        const { error } = userValidationSchema.validate({ email, password });
        if (error) throw new Error(error.details[0].message);

        const salt = await bcrypt.genSalt(10);
        const hashedPassword = await bcrypt.hash(password, salt);
        const newUser = new User({ email, password: hashedPassword });

        await newUser.save();
        return newUser;
    } catch (err) {
        console.error('Error inserting user:', err);
        throw err;
    }
};
module.exports = {
    User,
    insertUser,
};