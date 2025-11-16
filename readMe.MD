INSTALLATION STEPS:

1. Create a new directory for your project:
   mkdir prompt-hub
   cd prompt-hub

2. Initialize npm and install dependencies:
   npm init -y
   npm install express mongoose ejs bcrypt express-session method-override
   npm install --save-dev nodemon

3. Create the directory structure:
   mkdir views public
   mkdir views/partials (optional for future use)

4. Create the main server.js file with the code above

5. Create all EJS template files in the views directory:
   - views/layout.ejs
   - views/index.ejs
   - views/register.ejs
   - views/login.ejs
   - views/dashboard.ejs
   - views/create.ejs
   - views/edit.ejs
   - views/prompt.ejs
   - views/search.ejs

6. Make sure MongoDB is installed and running on your system:
   - Install MongoDB Community Edition
   - Start MongoDB service: mongod
   - The app will create a database called 'prompthub'

7. Update package.json scripts section:
   "scripts": {
     "start": "node server.js",
     "dev": "nodemon server.js"
   }

8. Run the application:
   npm run dev (for development with auto-restart)
   or
   npm start (for production)

9. Open your browser and go to http://localhost:3000

FEATURES INCLUDED:

✅ User Registration & Login (with bcrypt password hashing)
✅ Session-based authentication (no JWT for simplicity)
✅ Public prompt browsing (no login required)
✅ User dashboard to manage own prompts
✅ Create, edit, and delete prompts
✅ Public/private prompt visibility
✅ Prompt categorization and tagging
✅ Search functionality by title, content, tags, and category
✅ Responsive basic styling
✅ MongoDB integration with Mongoose

PROMPT-SPECIFIC FEATURES:

- Categories: Writing, Coding, Creative, Business, Education, Marketing, Other
- Tags system for better organization
- Public/Private visibility toggle
- Full-text search across title, content, and tags
- Author attribution
- Creation and update timestamps

SECURITY FEATURES:

- Password hashing with bcrypt
- Session-based authentication
- Authorization checks (users can only edit/delete their own prompts)
- Input validation and error handling

USAGE:

1. Register a new account or login
2. Browse public prompts on the home page
3. Click on any prompt to view it in full
4. Create new prompts from the dashboard
5. Manage your prompts (edit/delete) from dashboard
6. Use search to find specific prompts by keyword or category
7. Toggle prompt visibility between public and private

This is a complete, beginner-friendly prompt hub application that mirrors Medium's functionality but focuses on AI prompts instead of blog posts.