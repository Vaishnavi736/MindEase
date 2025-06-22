const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcryptjs');
const session = require('express-session');
const bodyParser = require('body-parser');
const path = require('path');

const app = express();
const PORT = process.env.PORT || 3001;

// Middleware
app.use(bodyParser.urlencoded({ extended: true }));
app.use(bodyParser.json());
app.use(express.static('public'));
app.use(express.static('views'));

// Session setup
app.use(session({
    secret: 'mindease-secret-key',
    resave: false,
    saveUninitialized: false,
    cookie: { secure: false }
}));

// SQLite database setup
const db = new sqlite3.Database('./mindease.db', (err) => {
    if (err) {
        console.error('Error opening database:', err);
    } else {
        console.log('Connected to SQLite database');
        createTables();
    }
});

// Create tables
function createTables() {
    db.serialize(() => {
        // Users table
        db.run(`CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            email TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP
        )`);

        // Moods table
        db.run(`CREATE TABLE IF NOT EXISTS moods (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            mood TEXT NOT NULL,
            date DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users (id)
        )`);

        // Journals table
        db.run(`CREATE TABLE IF NOT EXISTS journals (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            entry TEXT NOT NULL,
            date DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users (id)
        )`);
    });
}

// Routes
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'views', 'index.html'));
});

app.get('/signup', (req, res) => {
    res.sendFile(path.join(__dirname, 'views', 'signup.html'));
});

app.post('/signup', async (req, res) => {
    try {
        const { name, email, password } = req.body;
        console.log('Signup attempt for email:', email);
        
        // Check if email already exists
        db.get('SELECT id FROM users WHERE email = ?', [email], async (err, row) => {
            if (err) {
                console.error('Database error during signup:', err);
                return res.json({ success: false, error: 'Database error' });
            }
            
            if (row) {
                console.log('Email already exists:', email);
                return res.json({ success: false, error: 'Email already exists' });
            }
            
            console.log('Creating new user...');
            
            // Hash password
            const hashedPassword = await bcrypt.hash(password, 10);
            
            // Create new user
            db.run('INSERT INTO users (name, email, password) VALUES (?, ?, ?)', 
                [name, email, hashedPassword], function(err) {
                if (err) {
                    console.error('Failed to create user:', err);
                    return res.json({ success: false, error: 'Failed to create user' });
                }
                console.log('User created successfully with ID:', this.lastID);
                res.json({ success: true, redirect: '/login.html' });
            });
        });
    } catch (error) {
        console.error('Signup error:', error);
        res.json({ success: false, error: 'Something went wrong' });
    }
});

app.get('/login', (req, res) => {
    res.sendFile(path.join(__dirname, 'views', 'login.html'));
});

app.post('/login', async (req, res) => {
    try {
        const { email, password } = req.body;
        console.log('Login attempt for email:', email);
        
        // Find user
        db.get('SELECT * FROM users WHERE email = ?', [email], async (err, user) => {
            if (err) {
                console.error('Database error during login:', err);
                return res.json({ success: false, error: 'Database error' });
            }
            
            if (!user) {
                console.log('User not found for email:', email);
                return res.json({ success: false, error: 'Invalid email or password' });
            }
            
            console.log('User found, checking password...');
            
            // Check password
            const isValidPassword = await bcrypt.compare(password, user.password);
            if (!isValidPassword) {
                console.log('Invalid password for user:', email);
                return res.json({ success: false, error: 'Invalid email or password' });
            }
            
            console.log('Login successful for user:', user.name);
            
            // Set session
            req.session.userId = user.id;
            req.session.userName = user.name;
            res.json({ success: true, redirect: '/dashboard.html' });
        });
    } catch (error) {
        console.error('Login error:', error);
        res.json({ success: false, error: 'Something went wrong' });
    }
});

app.get('/dashboard', (req, res) => {
    if (!req.session.userId) {
        return res.redirect('/login.html');
    }
    res.sendFile(path.join(__dirname, 'views', 'dashboard.html'));
});

app.get('/api/user-data', (req, res) => {
    if (!req.session.userId) {
        return res.json({ error: 'Not authenticated' });
    }
    
    const userId = req.session.userId;
    
    // Get moods
    db.all('SELECT * FROM moods WHERE user_id = ? ORDER BY date DESC LIMIT 7', [userId], (err, moods) => {
        if (err) {
            return res.json({ error: 'Database error' });
        }
        
        // Get journals
        db.all('SELECT * FROM journals WHERE user_id = ? ORDER BY date DESC LIMIT 5', [userId], (err, journals) => {
            if (err) {
                return res.json({ error: 'Database error' });
            }
            
            res.json({ 
                userName: req.session.userName, 
                moods: moods || [], 
                journals: journals || [] 
            });
        });
    });
});

app.post('/mood', (req, res) => {
    if (!req.session.userId) {
        return res.json({ success: false, error: 'Not authenticated' });
    }
    
    const { mood } = req.body;
    const userId = req.session.userId;
    
    db.run('INSERT INTO moods (user_id, mood) VALUES (?, ?)', [userId, mood], function(err) {
        if (err) {
            return res.json({ success: false, error: 'Failed to save mood' });
        }
        res.json({ success: true });
    });
});

app.post('/journal', (req, res) => {
    if (!req.session.userId) {
        return res.json({ success: false, error: 'Not authenticated' });
    }
    
    const { entry } = req.body;
    const userId = req.session.userId;
    
    db.run('INSERT INTO journals (user_id, entry) VALUES (?, ?)', [userId, entry], function(err) {
        if (err) {
            return res.json({ success: false, error: 'Failed to save journal' });
        }
        res.json({ success: true });
    });
});

app.get('/logout', (req, res) => {
    req.session.destroy();
    res.redirect('/');
});

// Admin route to view database data
app.get('/admin', (req, res) => {
    let html = `
    <!DOCTYPE html>
    <html>
    <head>
        <title>MindEase - Database Admin</title>
        <style>
            body { font-family: Arial, sans-serif; margin: 20px; background: #f5f5f5; }
            .container { max-width: 1200px; margin: 0 auto; }
            .section { background: white; padding: 20px; margin: 20px 0; border-radius: 10px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
            h1, h2 { color: #333; }
            table { width: 100%; border-collapse: collapse; margin: 10px 0; }
            th, td { padding: 10px; text-align: left; border-bottom: 1px solid #ddd; }
            th { background: #667eea; color: white; }
            tr:hover { background: #f9f9f9; }
            .btn { padding: 10px 20px; background: #667eea; color: white; text-decoration: none; border-radius: 5px; margin: 5px; }
            .btn:hover { background: #5a67d8; }
            .password { color: #999; font-style: italic; }
        </style>
    </head>
    <body>
        <div class="container">
            <h1>🧠 MindEase Database Admin</h1>
            <a href="/" class="btn">← Back to Home</a>
            <a href="/admin" class="btn">🔄 Refresh Data</a>
    `;

    // Get users
    db.all('SELECT id, name, email, created_at FROM users ORDER BY created_at DESC', [], (err, users) => {
        if (err) {
            html += `<div class="section"><h2>Error loading users: ${err.message}</h2></div>`;
        } else {
            html += `
            <div class="section">
                <h2>👥 Users (${users.length})</h2>
                <table>
                    <tr><th>ID</th><th>Name</th><th>Email</th><th>Created</th></tr>
            `;
            users.forEach(user => {
                html += `<tr><td>${user.id}</td><td>${user.name}</td><td>${user.email}</td><td>${user.created_at}</td></tr>`;
            });
            html += `</table></div>`;
        }

        // Get moods
        db.all(`
            SELECT m.id, m.mood, m.date, u.name as user_name 
            FROM moods m 
            JOIN users u ON m.user_id = u.id 
            ORDER BY m.date DESC 
            LIMIT 20
        `, [], (err, moods) => {
            if (err) {
                html += `<div class="section"><h2>Error loading moods: ${err.message}</h2></div>`;
            } else {
                html += `
                <div class="section">
                    <h2>😊 Recent Moods (${moods.length})</h2>
                    <table>
                        <tr><th>ID</th><th>User</th><th>Mood</th><th>Date</th></tr>
                `;
                moods.forEach(mood => {
                    html += `<tr><td>${mood.id}</td><td>${mood.user_name}</td><td>${mood.mood}</td><td>${mood.date}</td></tr>`;
                });
                html += `</table></div>`;
            }

            // Get journals
            db.all(`
                SELECT j.id, j.entry, j.date, u.name as user_name 
                FROM journals j 
                JOIN users u ON j.user_id = u.id 
                ORDER BY j.date DESC 
                LIMIT 20
            `, [], (err, journals) => {
                if (err) {
                    html += `<div class="section"><h2>Error loading journals: ${err.message}</h2></div>`;
                } else {
                    html += `
                    <div class="section">
                        <h2>📝 Recent Journal Entries (${journals.length})</h2>
                        <table>
                            <tr><th>ID</th><th>User</th><th>Entry</th><th>Date</th></tr>
                    `;
                    journals.forEach(journal => {
                        const shortEntry = journal.entry.length > 50 ? journal.entry.substring(0, 50) + '...' : journal.entry;
                        html += `<tr><td>${journal.id}</td><td>${journal.user_name}</td><td>${shortEntry}</td><td>${journal.date}</td></tr>`;
                    });
                    html += `</table></div>`;
                }

                // Get database stats
                db.get('SELECT COUNT(*) as userCount FROM users', [], (err, userCount) => {
                    db.get('SELECT COUNT(*) as moodCount FROM moods', [], (err, moodCount) => {
                        db.get('SELECT COUNT(*) as journalCount FROM journals', [], (err, journalCount) => {
                            html += `
                            <div class="section">
                                <h2>📊 Database Statistics</h2>
                                <p><strong>Total Users:</strong> ${userCount.userCount}</p>
                                <p><strong>Total Mood Entries:</strong> ${moodCount.moodCount}</p>
                                <p><strong>Total Journal Entries:</strong> ${journalCount.journalCount}</p>
                            </div>
                            </div>
                            </body>
                            </html>
                            `;
                            res.send(html);
                        });
                    });
                });
            });
        });
    });
});

app.listen(PORT, () => {
    console.log(`MindEase is running on http://localhost:${PORT}`);
    console.log(`Admin panel: http://localhost:${PORT}/admin`);
}); 