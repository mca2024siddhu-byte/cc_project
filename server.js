const express = require('express');
const mongoose = require('mongoose');
const path = require('path');
const bcrypt = require('bcryptjs');
const session = require('express-session');
const multer = require('multer');
const fs = require('fs');


const app = express();
const PORT = 3000;

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
    // Generate unique filename with timestamp
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
    // Check file types
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
  secret: 'your-secret-key',
  resave: false,
  saveUninitialized: false,
  cookie: { secure: false } // set to true in production with HTTPS
}));

// MongoDB connection
mongoose.connect('mongodb://localhost:27017/express-blog')
  .then(() => console.log('Connected to MongoDB'))
  .catch(err => console.error('MongoDB connection error:', err));

// User Schema
const userSchema = new mongoose.Schema({
  username: { type: String, unique: true, required: true },
  email: { type: String, unique: true, required: true },
  password: { type: String, required: true },
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
  headerImage: { type: String }, // Path to header image
  video: { type: String }, // Path to video
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

// Middleware to make user available to all templates
app.use((req, res, next) => {
  res.locals.user = req.session.user || null;
  next();
});

// Routes

// Edit blog page
app.get('/blog/:id/edit', async (req, res) => {
  if (!req.session.user) {
    return res.redirect('/login');
  }
  
  try {
    const blog = await Blog.findById(req.params.id);
    
    if (!blog) {
      return res.status(404).render('404');
    }
    
    // Check if user owns the blog
    if (blog.authorId.toString() !== req.session.user.id) {
      return res.status(403).render('error', { error: 'You can only edit your own blogs' });
    }
    
    res.render('edit-blog', { blog, error: null, success: null });
  } catch (error) {
    console.error('Error loading blog for edit:', error);
    res.redirect('/profile');
  }
});

// Update blog handler
app.post('/blog/:id/edit', upload.fields([
  { name: 'headerImage', maxCount: 1 },
  { name: 'video', maxCount: 1 }
]), async (req, res) => {
  if (!req.session.user) {
    return res.redirect('/login');
  }
  
  try {
    const { title, content, removeHeaderImage, removeVideo } = req.body;
    const blogId = req.params.id;
    
    // Check if user owns the blog
    const existingBlog = await Blog.findById(blogId);
    if (!existingBlog || existingBlog.authorId.toString() !== req.session.user.id) {
      return res.status(403).render('error', { error: 'You can only edit your own blogs' });
    }
    
    const updateData = {
      title,
      content,
      updatedAt: new Date()
    };
    
    // Handle header image
    if (req.files && req.files.headerImage) {
      updateData.headerImage = '/uploads/' + req.files.headerImage[0].filename;
    } else if (removeHeaderImage === 'on') {
      updateData.headerImage = null;
    }
    
    // Handle video
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
app.post('/blog/:id/delete', async (req, res) => {
  if (!req.session.user) {
    return res.redirect('/login');
  }
  
  try {
    const blogId = req.params.id;
    
    // Check if user owns the blog
    const blog = await Blog.findById(blogId);
    if (!blog || blog.authorId.toString() !== req.session.user.id) {
      return res.status(403).json({ error: 'You can only delete your own blogs' });
    }
    
    // Delete the blog and its comments
    await Blog.findByIdAndDelete(blogId);
    await Comment.deleteMany({ blogId });
    
    res.json({ success: true });
  } catch (error) {
    console.error('Error deleting blog:', error);
    res.status(500).json({ error: 'Failed to delete blog' });
  }
});

// Home page - Show all blogs
app.get('/', async (req, res) => {
  try {
    const blogs = await Blog.find()
      .populate('authorId', 'username')
      .sort({ createdAt: -1 });
    
    // Get comment counts for each blog
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
      error: null  // Add this line
    });
  } catch (error) {
    console.error('Error loading blogs:', error);
    res.render('index', { 
      blogs: [], 
      error: 'Failed to load blogs' 
    });
  }
});

// Login page
app.get('/login', (req, res) => {
  res.render('login', { error: null });
});

// Login handler
app.post('/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    
    const user = await User.findOne({ email });
    if (!user) {
      return res.render('login', { error: 'Invalid email or password' });
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
  res.render('register', { error: null });
});

// Register handler
app.post('/register', async (req, res) => {
  try {
    const { username, email, password } = req.body;
    
    // Check if user exists
    const existingUser = await User.findOne({ 
      $or: [{ email }, { username }] 
    });
    
    if (existingUser) {
      return res.render('register', { error: 'User already exists with this email or username' });
    }
    
    // Hash password
    const hashedPassword = await bcrypt.hash(password, 10);
    
    // Create user
    const user = await User.create({
      username,
      email,
      password: hashedPassword
    });
    
    // Auto-login after registration
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

// Profile page
app.get('/profile', async (req, res) => {
  if (!req.session.user) {
    return res.redirect('/login');
  }
  
  try {
    // Get user's blogs
    const userBlogs = await Blog.find({ authorId: req.session.user.id })
      .sort({ createdAt: -1 });
    
    // Get user details
    const user = await User.findById(req.session.user.id);
    
    // Get stats
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
app.get('/profile/edit', (req, res) => {
  if (!req.session.user) {
    return res.redirect('/login');
  }
  res.render('edit-profile', { error: null, success: null });
});

// Update profile handler
app.post('/profile/edit', upload.single('profilePicture'), async (req, res) => {
  if (!req.session.user) {
    return res.redirect('/login');
  }
  
  try {
    const { username, email, bio } = req.body;
    const updateData = { username, email, bio };
    
    // Check if username/email already exists (excluding current user)
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
    
    // Handle profile picture upload
    if (req.file) {
      updateData.profilePicture = '/uploads/' + req.file.filename;
    }
    
    // Update user
    const updatedUser = await User.findByIdAndUpdate(
      req.session.user.id,
      updateData,
      { new: true }
    );
    
    // Update session
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

// Logout
app.post('/logout', (req, res) => {
  req.session.destroy();
  res.redirect('/');
});

// Create blog page (protected)
app.get('/create', (req, res) => {
  if (!req.session.user) {
    return res.redirect('/login');
  }
  res.render('create', { error: null });
});

// Create blog handler
app.post('/create', upload.fields([
  { name: 'headerImage', maxCount: 1 },
  { name: 'video', maxCount: 1 }
]), async (req, res) => {
  if (!req.session.user) {
    return res.redirect('/login');
  }
  
  try {
    const { title, content } = req.body;
    
    const blogData = {
      title,
      content,
      author: req.session.user.username,
      authorId: req.session.user.id
    };
    
    // Add header image path if uploaded
    if (req.files && req.files.headerImage) {
      blogData.headerImage = '/uploads/' + req.files.headerImage[0].filename;
    }
    
    // Add video path if uploaded
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

// Blog detail page
app.get('/blog/:id', async (req, res) => {
  try {
    const blog = await Blog.findById(req.params.id)
      .populate('authorId', 'username');
    
    if (!blog) {
      return res.status(404).render('404');
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
    res.status(500).render('error', { error: 'Failed to load blog' });
  }
});

// Add comment
app.post('/blog/:id/comment', async (req, res) => {
  if (!req.session.user) {
    return res.redirect('/login');
  }
  
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
app.post('/blog/:id/like', async (req, res) => {
  if (!req.session.user) {
    return res.status(401).json({ error: 'Not authenticated' });
  }
  
  try {
    const blog = await Blog.findById(req.params.id);
    
    if (!blog) {
      return res.status(404).json({ error: 'Blog not found' });
    }
    
    const hasLiked = blog.likes.includes(req.session.user.id);
    
    if (hasLiked) {
      // Unlike
      await Blog.findByIdAndUpdate(req.params.id, {
        $pull: { likes: req.session.user.id }
      });
    } else {
      // Like
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

// Start server
app.listen(PORT, () => {
  console.log(`Blog running on http://localhost:${PORT}`);
});