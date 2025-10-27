require('dotenv').config();

const express = require('express');
const mongoose = require('mongoose');
const path = require('path');
const bcrypt = require('bcryptjs');
const session = require('express-session');
const multer = require('multer');
const fs = require('fs');

const app = express();
const PORT = process.env.PORT || 3000;

// Create uploads directory if it doesn't exist
const uploadsDir = path.join(__dirname, 'public/uploads');
if (!fs.existsSync(uploadsDir)) {
  fs.mkdirSync(uploadsDir, { recursive: true });
}

// Configure multer for file uploads
const storage = multer.diskStorage({
  destination: function (req, file, cb) {
    cb(null, 'public/uploads/');
  },
  filename: function (req, file, cb) {
    const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1E9);
    cb(null, file.fieldname + '-' + uniqueSuffix + path.extname(file.originalname));
  }
});

const upload = multer({
  storage: storage,
  limits: {
    fileSize: 10 * 1024 * 1024 // 10MB limit
  },
  fileFilter: function (req, file, cb) {
    if (file.mimetype.startsWith('image/')) {
      cb(null, true);
    } else if (file.mimetype.startsWith('video/')) {
      cb(null, true);
    } else {
      cb(new Error('Only images and videos are allowed!'), false);
    }
  }
});

// Middleware
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));
app.use(express.urlencoded({ extended: true }));
app.use(express.static('public'));

// Session middleware
app.use(session({
  secret: process.env.SESSION_SECRET || 'your-secret-key',
  resave: false,
  saveUninitialized: false,
  cookie: { secure: false }
}));

// MongoDB connection - USING YOUR AZURE COSMOS DB
const MONGODB_URI = process.env.MONGODB_URI || 'mongodb://localhost:27017/express-blog';

console.log('🔧 Connecting to MongoDB...');
mongoose.connect(MONGODB_URI)
  .then(() => {
    console.log('✅ Connected to MongoDB successfully!');
    console.log('📊 Database:', mongoose.connection.name);
  })
  .catch(err => {
    console.error('❌ MongoDB connection error:', err);
    console.log('💡 Trying local MongoDB as fallback...');
    // Fallback to local MongoDB
    mongoose.connect('mongodb://localhost:27017/express-blog')
      .then(() => console.log('✅ Connected to local MongoDB'))
      .catch(err => console.error('❌ Local MongoDB also failed:', err));
  });

// User Schema
const userSchema = new mongoose.Schema({
  username: { type: String, unique: true, required: true },
  email: { type: String, unique: true, required: true },
  password: { type: String },
  googleId: { type: String }, // For Google OAuth users
  profilePicture: { type: String, default: '/uploads/default-avatar.png' },
  bio: { type: String, default: '' },
  createdAt: { type: Date, default: Date.now }
});

const User = mongoose.model('User', userSchema);

// Blog Schema
const blogSchema = new mongoose.Schema({
  title: { type: String, required: true },
  content: { type: String, required: true },
  author: { type: String, required: true },
  authorId: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
  headerImage: { type: String },
  video: { type: String },
  likes: [{ type: mongoose.Schema.Types.ObjectId, ref: 'User' }],
  createdAt: { type: Date, default: Date.now },
  updatedAt: { type: Date, default: Date.now }
});

const Blog = mongoose.model('Blog', blogSchema);

// Comment Schema
const commentSchema = new mongoose.Schema({
  content: { type: String, required: true },
  author: { type: String, required: true },
  authorId: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
  blogId: { type: mongoose.Schema.Types.ObjectId, ref: 'Blog', required: true },
  createdAt: { type: Date, default: Date.now }
});

const Comment = mongoose.model('Comment', commentSchema);

// ==================== IMPROVED AZURE EASY AUTH INTEGRATION ====================

app.use(async (req, res, next) => {
  try {
    // Check if user is authenticated via Azure Easy Auth
    const userJson = req.headers['x-ms-client-principal'];
    
    if (userJson) {
      const userBuffer = Buffer.from(userJson, 'base64');
      const azureUser = JSON.parse(userBuffer.toString());
      
      // Find or create user in our database
      let user = await User.findOne({ 
        $or: [
          { email: azureUser.userDetails },
          { googleId: azureUser.userId }
        ]
      });
      
      if (!user) {
        // Create new user from Azure Easy Auth
        user = await User.create({
          username: azureUser.userDetails.split('@')[0],
          email: azureUser.userDetails,
          googleId: azureUser.userId,
          profilePicture: '/uploads/default-avatar.png'
        });
      }
      
      // Check if session user matches Azure user
      const sessionUserId = req.session.user?.id?.toString();
      const currentUserId = user._id.toString();
      
      // If session user is different from Azure user, clear session and update
      if (sessionUserId && sessionUserId !== currentUserId) {
        console.log('🔄 User changed, updating session...');
        req.session.destroy((err) => {
          if (err) console.error('Error destroying session:', err);
        });
      }
      
      // Update session with current user
      req.session.user = {
        id: user._id,
        username: user.username,
        email: user.email,
        googleId: user.googleId
      };
      
      console.log('🔐 Session updated for:', user.username);
    } else {
      // No Azure auth - clear session if it exists
      if (req.session.user) {
        console.log('🚫 No Azure auth, clearing session');
        req.session.destroy((err) => {
          if (err) console.error('Error destroying session:', err);
        });
      }
    }
    
    // Make user available to all templates
    res.locals.user = req.session.user || null;
    res.locals.isAuthenticated = !!req.session.user;
    
  } catch (error) {
    console.error('Error in auth middleware:', error);
    res.locals.user = null;
    res.locals.isAuthenticated = false;
  }
  next();
});

// Protect routes that require authentication
const requireAuth = (req, res, next) => {
  if (!res.locals.isAuthenticated) {
    // Redirect to Google login, then back to original URL
    return res.redirect(`/.auth/login/google?post_login_redirect_uri=${encodeURIComponent(req.originalUrl)}`);
  }
  next();
};

// ==================== ROUTES ====================

// Home page - Show all blogs (Public - no auth required)
app.get('/', async (req, res) => {
  try {
    const blogs = await Blog.find()
      .populate('authorId', 'username')
      .sort({ createdAt: -1 });
    
    const blogsWithCounts = await Promise.all(
      blogs.map(async (blog) => {
        const commentCount = await Comment.countDocuments({ blogId: blog._id });
        return {
          ...blog.toObject(),
          commentCount
        };
      })
    );
    
    res.render('index', { 
      blogs: blogsWithCounts,
      error: null
    });
  } catch (error) {
    console.error('Error loading blogs:', error);
    res.render('index', { 
      blogs: [], 
      error: 'Failed to load blogs' 
    });
  }
});

// Blog detail page - FIXED ERROR HANDLING (Public - no auth required)
app.get('/blog/:id', async (req, res) => {
  try {
    const blog = await Blog.findById(req.params.id)
      .populate('authorId', 'username');
    
    if (!blog) {
      return res.status(404).send('Blog not found');
    }
    
    const comments = await Comment.find({ blogId: req.params.id })
      .populate('authorId', 'username')
      .sort({ createdAt: 1 });
    
    res.render('blog', { 
      blog: blog.toObject(), 
      comments,
      user: req.session.user 
    });
  } catch (error) {
    console.error('Error loading blog:', error);
    res.status(500).send('Failed to load blog');
  }
});

// ==================== AUTHENTICATION ROUTES ====================

// Login page (Traditional email/password)
app.get('/login', (req, res) => {
  // If already authenticated, redirect to home
  if (res.locals.isAuthenticated) {
    return res.redirect('/');
  }
  res.render('login', { error: null });
});

// Login handler (Traditional email/password)
app.post('/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    
    const user = await User.findOne({ email });
    if (!user) {
      return res.render('login', { error: 'Invalid email or password' });
    }
    
    // Check if user has a password (Google users might not have one)
    if (!user.password) {
      return res.render('login', { 
        error: 'Please use Google Sign-In for this account',
        googleAuthUrl: '/.auth/login/google?post_login_redirect_uri=/'
      });
    }
    
    const validPassword = await bcrypt.compare(password, user.password);
    if (!validPassword) {
      return res.render('login', { error: 'Invalid email or password' });
    }
    
    req.session.user = {
      id: user._id,
      username: user.username,
      email: user.email
    };
    
    res.redirect('/');
  } catch (error) {
    console.error('Login error:', error);
    res.render('login', { error: 'An error occurred during login' });
  }
});

// Register page
app.get('/register', (req, res) => {
  // If already authenticated, redirect to home
  if (res.locals.isAuthenticated) {
    return res.redirect('/');
  }
  res.render('register', { error: null });
});

// Register handler (Traditional email/password)
app.post('/register', async (req, res) => {
  try {
    const { username, email, password } = req.body;
    
    const existingUser = await User.findOne({ 
      $or: [{ email }, { username }] 
    });
    
    if (existingUser) {
      return res.render('register', { error: 'User already exists with this email or username' });
    }
    
    const hashedPassword = await bcrypt.hash(password, 10);
    
    const user = await User.create({
      username,
      email,
      password: hashedPassword
    });
    
    req.session.user = {
      id: user._id,
      username: user.username,
      email: user.email
    };
    
    res.redirect('/');
  } catch (error) {
    console.error('Registration error:', error);
    res.render('register', { error: 'Registration failed' });
  }
});

// Logout
app.post('/logout', (req, res) => {
  req.session.destroy((err) => {
    if (err) {
      console.error('Logout error:', err);
    }
    // Redirect to Azure logout or home
    res.redirect('/.auth/logout?post_logout_redirect_uri=/');
  });
});

// ==================== PROTECTED ROUTES (Require Authentication) ====================

// Profile page
app.get('/profile', requireAuth, async (req, res) => {
  try {
    const userBlogs = await Blog.find({ authorId: req.session.user.id })
      .sort({ createdAt: -1 });
    
    const user = await User.findById(req.session.user.id);
    
    const totalLikes = await Blog.aggregate([
      { $match: { authorId: new mongoose.Types.ObjectId(req.session.user.id) } },
      { $project: { likesCount: { $size: "$likes" } } },
      { $group: { _id: null, total: { $sum: "$likesCount" } } }
    ]);
    
    const totalComments = await Comment.countDocuments({ 
      authorId: req.session.user.id 
    });
    
    res.render('profile', {
      user: {
        ...user.toObject(),
        totalBlogs: userBlogs.length,
        totalLikes: totalLikes[0]?.total || 0,
        totalComments: totalComments
      },
      blogs: userBlogs
    });
  } catch (error) {
    console.error('Error loading profile:', error);
    res.redirect('/');
  }
});

// Update profile route
app.get('/profile/edit', requireAuth, (req, res) => {
  res.render('edit-profile', { error: null, success: null });
});

// Update profile handler
app.post('/profile/edit', requireAuth, upload.single('profilePicture'), async (req, res) => {
  try {
    const { username, email, bio } = req.body;
    const updateData = { username, email, bio };
    
    const existingUser = await User.findOne({
      $and: [
        { _id: { $ne: req.session.user.id } },
        { $or: [{ email }, { username }] }
      ]
    });
    
    if (existingUser) {
      return res.render('edit-profile', { 
        error: 'Username or email already exists',
        success: null
      });
    }
    
    if (req.file) {
      updateData.profilePicture = '/uploads/' + req.file.filename;
    }
    
    const updatedUser = await User.findByIdAndUpdate(
      req.session.user.id,
      updateData,
      { new: true }
    );
    
    req.session.user = {
      id: updatedUser._id,
      username: updatedUser.username,
      email: updatedUser.email
    };
    
    res.render('edit-profile', { 
      error: null,
      success: 'Profile updated successfully!' 
    });
  } catch (error) {
    console.error('Error updating profile:', error);
    res.render('edit-profile', { 
      error: 'Failed to update profile',
      success: null
    });
  }
});

// Create blog page
app.get('/create', requireAuth, (req, res) => {
  res.render('create', { error: null });
});

// Create blog handler
app.post('/create', requireAuth, upload.fields([
  { name: 'headerImage', maxCount: 1 },
  { name: 'video', maxCount: 1 }
]), async (req, res) => {
  try {
    const { title, content } = req.body;
    
    const blogData = {
      title,
      content,
      author: req.session.user.username,
      authorId: req.session.user.id
    };
    
    if (req.files && req.files.headerImage) {
      blogData.headerImage = '/uploads/' + req.files.headerImage[0].filename;
    }
    
    if (req.files && req.files.video) {
      blogData.video = '/uploads/' + req.files.video[0].filename;
    }
    
    await Blog.create(blogData);
    
    res.redirect('/');
  } catch (error) {
    console.error('Error creating blog:', error);
    res.render('create', { error: 'Failed to create blog' });
  }
});

// Edit blog page
app.get('/blog/:id/edit', requireAuth, async (req, res) => {
  try {
    const blog = await Blog.findById(req.params.id);
    
    if (!blog) {
      return res.status(404).send('Blog not found');
    }
    
    if (blog.authorId.toString() !== req.session.user.id) {
      return res.status(403).send('You can only edit your own blogs');
    }
    
    res.render('edit-blog', { blog, error: null, success: null });
  } catch (error) {
    console.error('Error loading blog for edit:', error);
    res.redirect('/profile');
  }
});

// Update blog handler
app.post('/blog/:id/edit', requireAuth, upload.fields([
  { name: 'headerImage', maxCount: 1 },
  { name: 'video', maxCount: 1 }
]), async (req, res) => {
  try {
    const { title, content, removeHeaderImage, removeVideo } = req.body;
    const blogId = req.params.id;
    
    const existingBlog = await Blog.findById(blogId);
    if (!existingBlog || existingBlog.authorId.toString() !== req.session.user.id) {
      return res.status(403).send('You can only edit your own blogs');
    }
    
    const updateData = {
      title,
      content,
      updatedAt: new Date()
    };
    
    if (req.files && req.files.headerImage) {
      updateData.headerImage = '/uploads/' + req.files.headerImage[0].filename;
    } else if (removeHeaderImage === 'on') {
      updateData.headerImage = null;
    }
    
    if (req.files && req.files.video) {
      updateData.video = '/uploads/' + req.files.video[0].filename;
    } else if (removeVideo === 'on') {
      updateData.video = null;
    }
    
    await Blog.findByIdAndUpdate(blogId, updateData);
    
    res.render('edit-blog', { 
      blog: { ...existingBlog.toObject(), ...updateData },
      error: null,
      success: 'Blog updated successfully!' 
    });
  } catch (error) {
    console.error('Error updating blog:', error);
    const blog = await Blog.findById(req.params.id);
    res.render('edit-blog', { 
      blog,
      error: 'Failed to update blog',
      success: null
    });
  }
});

// Delete blog
app.post('/blog/:id/delete', requireAuth, async (req, res) => {
  try {
    const blogId = req.params.id;
    
    const blog = await Blog.findById(blogId);
    if (!blog || blog.authorId.toString() !== req.session.user.id) {
      return res.status(403).json({ error: 'You can only delete your own blogs' });
    }
    
    await Blog.findByIdAndDelete(blogId);
    await Comment.deleteMany({ blogId });
    
    res.json({ success: true });
  } catch (error) {
    console.error('Error deleting blog:', error);
    res.status(500).json({ error: 'Failed to delete blog' });
  }
});

// Add comment
app.post('/blog/:id/comment', requireAuth, async (req, res) => {
  try {
    const { content } = req.body;
    
    await Comment.create({
      content,
      author: req.session.user.username,
      authorId: req.session.user.id,
      blogId: req.params.id
    });
    
    res.redirect(`/blog/${req.params.id}`);
  } catch (error) {
    console.error('Error adding comment:', error);
    res.redirect(`/blog/${req.params.id}`);
  }
});

// Like blog
app.post('/blog/:id/like', requireAuth, async (req, res) => {
  try {
    const blog = await Blog.findById(req.params.id);
    
    if (!blog) {
      return res.status(404).json({ error: 'Blog not found' });
    }
    
    const hasLiked = blog.likes.includes(req.session.user.id);
    
    if (hasLiked) {
      await Blog.findByIdAndUpdate(req.params.id, {
        $pull: { likes: req.session.user.id }
      });
    } else {
      await Blog.findByIdAndUpdate(req.params.id, {
        $addToSet: { likes: req.session.user.id }
      });
    }
    
    const updatedBlog = await Blog.findById(req.params.id);
    
    res.json({
      likes: updatedBlog.likes.length,
      hasLiked: !hasLiked
    });
  } catch (error) {
    console.error('Error toggling like:', error);
    res.status(500).json({ error: 'Failed to toggle like' });
  }
});

// ==================== HEALTH AND DEBUG ROUTES ====================

// Health check endpoint
app.get('/health', (req, res) => {
  const health = {
    status: 'healthy',
    timestamp: new Date().toISOString(),
    database: mongoose.connection.readyState === 1 ? 'connected' : 'disconnected',
    authentication: {
      isAuthenticated: res.locals.isAuthenticated,
      user: res.locals.user ? 'logged_in' : 'guest'
    }
  };
  
  res.status(200).json(health);
});

// Debug endpoint to check Azure Easy Auth headers
app.get('/debug-auth', (req, res) => {
  const authInfo = {
    headers: {
      'x-ms-client-principal': req.headers['x-ms-client-principal'],
      'x-ms-client-principal-name': req.headers['x-ms-client-principal-name'],
      'x-ms-client-principal-id': req.headers['x-ms-client-principal-id']
    },
    session: req.session.user,
    locals: {
      user: res.locals.user,
      isAuthenticated: res.locals.isAuthenticated
    }
  };
  
  res.json(authInfo);
});

// ==================== ERROR HANDLERS ====================

// 404 handler
app.use((req, res) => {
  res.status(404).send(`
    <!DOCTYPE html>
    <html>
    <head><title>404 - Not Found</title></head>
    <body>
      <h1>404 - Page Not Found</h1>
      <a href="/">Go Home</a>
    </body>
    </html>
  `);
});

// Error handler 
app.use((error, req, res, next) => {
  console.error('Application error:', error);
  res.status(500).send(`
    <!DOCTYPE html>
    <html>
    <head><title>Error</title></head>
    <body>
      <h1>Something went wrong</h1>
      <p>${error.message}</p>
      <a href="/">Go Home</a>
    </body>
    </html>
  `);
});

// Start server
app.listen(PORT, '0.0.0.0', () => {
  console.log(`🚀 Blog running on http://localhost:${PORT}`);
  console.log(`🌍 Using: ${process.env.MONGODB_URI ? 'Azure Cosmos DB' : 'Local MongoDB'}`);
  console.log(`🔐 Authentication: Azure Easy Auth Integrated`);
});