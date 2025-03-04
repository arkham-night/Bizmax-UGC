// server.js
const express = require('express');
const bodyParser = require('body-parser');
const cors = require('cors');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const mongoose = require('mongoose');
const path = require('path');
const morgan = require('morgan');
const rateLimit = require('express-rate-limit');

// Configuration (dummy placeholders)
// All sensitive data will be managed via the admin panel in production.
const JWT_SECRET = "DUMMY_JWT_SECRET";
const MONGO_URI = "mongodb+srv://<username>:<password>@cluster0.mongodb.net/bizmax-ugc?retryWrites=true&w=majority";

mongoose.connect(MONGO_URI, { useNewUrlParser: true, useUnifiedTopology: true })
  .then(() => console.log("MongoDB connected"))
  .catch(err => console.error("MongoDB connection error:", err));

const app = express();
const PORT = process.env.PORT || 3000;

// Middleware
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));
app.use(cors());
app.use(express.static(path.join(__dirname, 'public')));
app.use(morgan('combined'));
const limiter = rateLimit({
  windowMs: 1 * 60 * 1000, // 1 minute
  max: 100
});
app.use(limiter);

// Mongoose Schemas
const userSchema = new mongoose.Schema({
  name: String,
  email: { type: String, unique: true },
  password: String,
  role: { type: String, default: 'user' },
  verified: { type: Boolean, default: false },
  businessDetails: Object,
  apiKeys: Object
});
const User = mongoose.model('User', userSchema);

const settingsSchema = new mongoose.Schema({
  razorpay: { key: String, endpoint: String, enabled: Boolean },
  openai: { key: String, endpoint: String, enabled: Boolean },
  tts: { key: String, endpoint: String, enabled: Boolean },
  avatarGen: { key: String, endpoint: String, enabled: Boolean },
  vpnDetection: { key: String, endpoint: String, enabled: Boolean },
  ipTracking: { key: String, endpoint: String, enabled: Boolean },
  jwtSecret: { type: String, default: JWT_SECRET }
});
const Settings = mongoose.model('Settings', settingsSchema);

// JWT Middleware
function verifyToken(req, res, next) {
  const token = req.headers['authorization'];
  if (!token) return res.status(403).send("No token provided.");
  jwt.verify(token, JWT_SECRET, (err, decoded) => {
    if (err) return res.status(500).send("Failed to authenticate token.");
    req.userId = decoded.id;
    req.userRole = decoded.role;
    next();
  });
}

// API Endpoints

// User Registration
app.post('/api/signup', async (req, res) => {
  const { name, email, password } = req.body;
  try {
    let hashedPassword = bcrypt.hashSync(password, 8);
    let newUser = new User({
      name,
      email,
      password: hashedPassword,
      role: 'user',
      verified: false,
      businessDetails: {},
      apiKeys: {}
    });
    await newUser.save();
    res.json({ message: "User registered successfully. Verification pending.", user: newUser });
  } catch (err) {
    res.status(500).send("Error registering user: " + err);
  }
});

// User Login
app.post('/api/login', async (req, res) => {
  const { email, password } = req.body;
  try {
    let user = await User.findOne({ email });
    if (!user) return res.status(404).send("User not found.");
    const passwordIsValid = bcrypt.compareSync(password, user.password);
    if (!passwordIsValid) return res.status(401).send("Invalid password.");
    const token = jwt.sign({ id: user._id, role: user.role }, JWT_SECRET, { expiresIn: 86400 });
    res.json({ message: "Login successful.", token, user });
  } catch (err) {
    res.status(500).send("Error logging in: " + err);
  }
});

// Dummy endpoint for content generation
app.post('/api/generate-content', verifyToken, (req, res) => {
  // Future integration: OpenAI GPT and TTS
  res.json({ content: "Coming Soon: AI generated content based on your input." });
});

// Dummy endpoint for payment upgrade (Razorpay placeholder)
app.post('/api/upgrade', verifyToken, (req, res) => {
  // Future integration: Razorpay payment gateway
  res.json({ message: "Upgrade functionality coming soon. Contact us for more details." });
});

// Dummy endpoint for IP/device tracking and VPN detection.
app.get('/api/track', verifyToken, (req, res) => {
  // Future integration: VPN detection and device tracking API
  res.json({ status: "Coming Soon: VPN detection and device tracking." });
});

// Admin Endpoints

app.get('/api/admin/users', verifyToken, async (req, res) => {
  if (req.userRole !== 'admin') return res.status(403).send("Access denied.");
  let users = await User.find({});
  res.json(users);
});

app.put('/api/admin/verify-user/:id', verifyToken, async (req, res) => {
  if (req.userRole !== 'admin') return res.status(403).send("Access denied.");
  try {
    let user = await User.findByIdAndUpdate(req.params.id, { verified: req.body.verified }, { new: true });
    if (!user) return res.status(404).send("User not found.");
    res.json({ message: "User verification updated.", user });
  } catch (err) {
    res.status(500).send("Error updating user: " + err);
  }
});

app.get('/api/admin/settings', verifyToken, async (req, res) => {
  if (req.userRole !== 'admin') return res.status(403).send("Access denied.");
  let settings = await Settings.findOne({});
  if (!settings) {
    settings = await new Settings({
      razorpay: { key: "DUMMY_RAZORPAY_KEY", endpoint: "https://dummy-razorpay.com/api", enabled: false },
      openai: { key: "DUMMY_OPENAI_KEY", endpoint: "https://dummy-openai.com/api", enabled: false },
      tts: { key: "DUMMY_TTS_KEY", endpoint: "https://dummy-tts.com/api", enabled: false },
      avatarGen: { key: "DUMMY_AVATAR_KEY", endpoint: "https://dummy-avatar.com/api", enabled: false },
      vpnDetection: { key: "DUMMY_VPN_KEY", endpoint: "https://dummy-vpn.com/api", enabled: false },
      ipTracking: { key: "DUMMY_IP_KEY", endpoint: "https://dummy-ip.com/api", enabled: false },
      jwtSecret: JWT_SECRET
    }).save();
  }
  res.json(settings);
});

app.put('/api/admin/settings', verifyToken, async (req, res) => {
  if (req.userRole !== 'admin') return res.status(403).send("Access denied.");
  try {
    let settings = await Settings.findOneAndUpdate({}, req.body, { new: true, upsert: true });
    res.json({ message: "Settings updated successfully.", settings });
  } catch (err) {
    res.status(500).send("Error updating settings: " + err);
  }
});

// Fallback route for client-side routing
app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'public/index.html'));
});

app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
