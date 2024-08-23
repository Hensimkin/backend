const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const speakeasy = require('speakeasy');
const qrcode = require('qrcode');
const bcrypt = require('bcrypt');

const app = express();
const port = 3001;

const corsOptions = {
  origin: 'http://localhost:3000',
  optionsSuccessStatus: 200
};

app.use(cors(corsOptions));
app.use(express.json());

// Connect to MongoDB
mongoose.connect('mongodb+srv://hensim97:ierbbYOtpY55jXjv@2fa.nqjiwke.mongodb.net/?retryWrites=true&w=majority&appName=2FA', {
  useNewUrlParser: true,
  useUnifiedTopology: true
}).then(() => {
  console.log('Connected to MongoDB');
}).catch(err => {
  console.error('Failed to connect to MongoDB', err);
});

// Define a User schema
const userSchema = new mongoose.Schema({
  username: { type: String, required: true, unique: true },
  password: { type: String, required: true },
  phoneNumber: { type: String, required: true },
  twoFactorSecret: { type: String },
  twoFactorEnabled: { type: Boolean, default: false }
});

// Create a User model
const User = mongoose.model('User', userSchema);

// Register endpoint
app.post('/register', async (req, res) => {
  const { username, password, phoneNumber } = req.body;

  if (!username || !password || !phoneNumber) {
    return res.status(400).send('Username, password, and phone number are required.');
  }

  try {
    // Generate a salt and hash the password
    const salt = await bcrypt.genSalt(10);
    const hashedPassword = await bcrypt.hash(password, salt);

    const secret = speakeasy.generateSecret({ name: `2FA-App (${username})` });
    const newUser = new User({
      username,
      password: hashedPassword,
      phoneNumber,
      twoFactorSecret: secret.base32,
      twoFactorEnabled: false
    });
    await newUser.save();

    qrcode.toDataURL(secret.otpauth_url, (err, data_url) => {
      if (err) {
        return res.status(500).send('Error generating QR code.');
      }
      res.status(200).send({ msg: 'User registered successfully.', qrCode: data_url });
    });

  } catch (err) {
    if (err.code === 11000) {
      res.status(409).send('User already exists.');
    } else {
      res.status(500).send('Error registering user.');
    }
  }
});

// Login endpoint
app.post('/login', async (req, res) => {
  const { username, password } = req.body;

  if (!username || !password) {
    return res.status(400).send('Username and password are required.');
  }

  try {
    const user = await User.findOne({ username });
    if (!user) {
      return res.status(401).send('Invalid username or password.');
    }

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      return res.status(401).send('Invalid username or password.');
    }

    // Generate a new 2FA secret and QR code
    const secret = speakeasy.generateSecret({ name: `2FA-App (${username})` });
    user.twoFactorSecret = secret.base32;
    user.twoFactorEnabled = false;
    await user.save();

    qrcode.toDataURL(secret.otpauth_url, (err, data_url) => {
      if (err) {
        return res.status(500).send('Error generating QR code.');
      }

      res.status(200).send({
        msg: 'Login successful. Please set up your new 2FA.',
        requires2FA: true,
        qrCode: data_url
      });
    });

  } catch (err) {
    res.status(500).send('Error logging in.');
  }
});

// Endpoint to get QR code for the logged-in user
app.get('/qrcode', async (req, res) => {
  const { username } = req.query;

  try {
    const user = await User.findOne({ username });
    if (!user) {
      return res.status(404).send('User not found.');
    }

    qrcode.toDataURL(`otpauth://totp/2FA-App (${username})?secret=${user.twoFactorSecret}`, (err, data_url) => {
      if (err) {
        return res.status(500).send('Error generating QR code.');
      }
      res.status(200).send({ qrCode: data_url });
    });
  } catch (err) {
    res.status(500).send('Errorrrrrr generating QR code.');
  }
});

// Endpoint to verify 2FA token
app.post('/verify-2fa', async (req, res) => {
  const { username, token } = req.body;

  try {
    const user = await User.findOne({ username });
    if (!user) {
      return res.status(404).send('User is not found.');
    }

    const verified = speakeasy.totp.verify({
      secret: user.twoFactorSecret,
      encoding: 'base32',
      token
    });

    if (!verified) {
      return res.status(401).send('Invalid 2FA token.');
    }

    user.twoFactorEnabled = true;
    await user.save();

    res.status(200).send('2FA setup confirmed.');
  } catch (err) {
    res.status(500).send('Error verifying 2FA token.');
  }
});

app.listen(port, () => {
  console.log(`Server is running at http://localhost:${port}`);
});
