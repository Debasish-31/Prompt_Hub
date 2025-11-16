const express = require('express');
const mongoose = require('mongoose');
const session = require('express-session');
const methodOverride = require('method-override');
const bcrypt = require('bcrypt');
const path = require('path');

const app = express();
const PORT = 3000;

// Connect to MongoDB
mongoose.connect('datbase string', {
  useNewUrlParser: true,
  useUnifiedTopology: true,
});

// User Schema
const userSchema = new mongoose.Schema({
  //id
  username: { type: String, required: true, unique: true },
  email: { type: String, required: true, unique: true },
  password: { type: String, required: true },
  createdAt: { type: Date, default: Date.now }
});

const User = mongoose.model('User', userSchema);

// Prompt Schema
const promptSchema = new mongoose.Schema({
  title: { type: String, required: true },
  content: { type: String, required: true },
  category: { type: String, required: true },
  tags: [String],
  author: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  isPublic: { type: Boolean, default: true },
  createdAt: { type: Date, default: Date.now },
  updatedAt: { type: Date, default: Date.now }
});

const Prompt = mongoose.model('Prompt', promptSchema);

const engine = require('ejs-mate');


// Middleware
app.use(express.urlencoded({ extended: true }));
app.use(express.json());
app.use(methodOverride('_method'));
app.use(express.static('public'));
app.engine('ejs', engine);
app.set('view engine', 'ejs');

// Session configuration
app.use(session({
  secret: 'your-secret-key-here',
  resave: false,
  saveUninitialized: false,
  cookie: { maxAge: 24 * 60 * 60 * 1000 } // 24 hours
}));

// Middleware to check if user is logged in
const requireAuth = (req, res, next) => {
  if (req.session.userId) {
    next();
  } else {
    res.redirect('/login');
  }
};

// Routes

// Home page - show all public prompts
app.get('/', async (req, res) => {
  try {
    const prompts = await Prompt.find({ isPublic: true })
      .populate('author', 'username')
      .sort({ createdAt: -1 });
    
    res.render('index', { 
      prompts, 
      user: req.session.userId ? await User.findById(req.session.userId) : null 
    });
  } catch (error) {
    console.error(error);
    res.status(500).send('Server Error');
  }
});

// Register page
app.get('/register', (req, res) => {
  res.render('register', { error: null });
});

// Register POST
app.post('/register', async (req, res) => {
  try {
    const { username, email, password } = req.body;
    
    // Check if user already exists
    const existingUser = await User.findOne({ 
      $or: [{ email }, { username }] 
    });
    
    if (existingUser) {
      return res.render('register', { 
        error: 'User with this email or username already exists' 
      });
    }
    
    // Hash password
    const hashedPassword = await bcrypt.hash(password, 10);
    
    // Create user
    const user = new User({
      username,
      email,
      password: hashedPassword
    });
    
    await user.save();
    req.session.userId = user._id;
    res.redirect('/dashboard');
  } catch (error) {
    console.error(error);
    res.render('register', { error: 'Something went wrong' });
  }
});

// Login page
app.get('/login', (req, res) => {
  res.render('login', { error: null });
});

// Login POST
app.post('/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    
    // Find user
    const user = await User.findOne({ email });
    if (!user) {
      return res.render('login', { error: 'Invalid email or password' });
    }
    
    // Check password
    const isValidPassword = await bcrypt.compare(password, user.password);
    if (!isValidPassword) {
      return res.render('login', { error: 'Invalid email or password' });
    }
    
    req.session.userId = user._id;
    res.redirect('/dashboard');
  } catch (error) {
    console.error(error);
    res.render('login', { error: 'Something went wrong' });
  }
});

// Logout
app.get('/logout', (req, res) => {
  req.session.destroy();
  res.redirect('/');
});

// Dashboard - user's prompts
app.get('/dashboard', requireAuth, async (req, res) => {
  try {
    const user = await User.findById(req.session.userId);
    const prompts = await Prompt.find({ author: req.session.userId })
      .sort({ createdAt: -1 });
    
    res.render('dashboard', { user, prompts });
  } catch (error) {
    console.error(error);
    res.status(500).send('Server Error');
  }
});

// View single prompt
app.get('/prompt/:id', async (req, res) => {
  try {
    const prompt = await Prompt.findById(req.params.id).populate('author', 'username');
    
    if (!prompt) {
      return res.status(404).send('Prompt not found');
    }
    
    // Check if prompt is public or user owns it
    if (!prompt.isPublic && (!req.session.userId || prompt.author._id.toString() !== req.session.userId)) {
      return res.status(403).send('Access denied');
    }
    
    res.render('prompt', { 
      prompt, 
      user: req.session.userId ? await User.findById(req.session.userId) : null 
    });
  } catch (error) {
    console.error(error);
    res.status(500).send('Server Error');
  }
});

// Create prompt page
app.get('/create', requireAuth, async (req, res) => {
  const user = await User.findById(req.session.userId);
  res.render('create', { user, error: null });
});

// Create prompt POST
app.post('/create', requireAuth, async (req, res) => {
  try {
    const { title, content, category, tags, isPublic } = req.body;
    
    const prompt = new Prompt({
      title,
      content,
      category,
      tags: tags ? tags.split(',').map(tag => tag.trim()) : [],
      author: req.session.userId,
      isPublic: isPublic === 'on'
    });
    
    await prompt.save();
    res.redirect('/dashboard');
  } catch (error) {
    console.error(error);
    const user = await User.findById(req.session.userId);
    res.render('create', { user, error: 'Failed to create prompt' });
  }
});

// Edit prompt page
app.get('/edit/:id', requireAuth, async (req, res) => {
  try {
    const prompt = await Prompt.findById(req.params.id);
    
    if (!prompt || prompt.author.toString() !== req.session.userId) {
      return res.status(403).send('Access denied');
    }
    
    const user = await User.findById(req.session.userId);
    res.render('edit', { prompt, user, error: null });
  } catch (error) {
    console.error(error);
    res.status(500).send('Server Error');
  }
});

// Edit prompt POST
app.put('/edit/:id', requireAuth, async (req, res) => {
  try {
    const { title, content, category, tags, isPublic } = req.body;
    
    const prompt = await Prompt.findById(req.params.id);
    
    if (!prompt || prompt.author.toString() !== req.session.userId) {
      return res.status(403).send('Access denied');
    }
    
    prompt.title = title;
    prompt.content = content;
    prompt.category = category;
    prompt.tags = tags ? tags.split(',').map(tag => tag.trim()) : [];
    prompt.isPublic = isPublic === 'on';
    prompt.updatedAt = new Date();
    
    await prompt.save();
    res.redirect('/dashboard');
  } catch (error) {
    console.error(error);
    res.status(500).send('Server Error');
  }
});

// Delete prompt
app.delete('/prompt/:id', requireAuth, async (req, res) => {
  try {
    const prompt = await Prompt.findById(req.params.id);
    
    if (!prompt || prompt.author.toString() !== req.session.userId) {
      return res.status(403).send('Access denied');
    }
    
    await Prompt.findByIdAndDelete(req.params.id);
    res.redirect('/dashboard');
  } catch (error) {
    console.error(error);
    res.status(500).send('Server Error');
  }
});

// Search prompts
app.get('/search', async (req, res) => {
  try {
    const { q, category } = req.query;
    let searchQuery = { isPublic: true };
    
    if (q) {
      searchQuery.$or = [
        { title: { $regex: q, $options: 'i' } },
        { content: { $regex: q, $options: 'i' } },
        { tags: { $in: [new RegExp(q, 'i')] } }
      ];
    }
    
    if (category && category !== 'all') {
      searchQuery.category = category;
    }
    
    const prompts = await Prompt.find(searchQuery)
      .populate('author', 'username')
      .sort({ createdAt: -1 });
    
    res.render('search', { 
      prompts, 
      query: q || '',
      selectedCategory: category || 'all',
      user: req.session.userId ? await User.findById(req.session.userId) : null 
    });
  } catch (error) {
    console.error(error);
    res.status(500).send('Server Error');
  }
});

app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});