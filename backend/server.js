/**
 * ALTITUDE BPO - ENHANCED TICKETING SYSTEM & IDENTITY MANAGER
 * Modern features: Comments, Replies, Real-time updates, Identity Provisioning
 * Version: 2.0.1 (Enterprise Edition)
 */

require('dotenv').config();

const express = require('express');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const Database = require('better-sqlite3');
const path = require('path');
const moment = require('moment');
const nodemailer = require('nodemailer');

const app = express();
const PORT = process.env.PORT || 5000; 
const SECRET_KEY = process.env.JWT_SECRET || "ALTITUDE_BPO_2026_SECURE_KEY";

// ==========================================
// ON-PREMISES EXCHANGE EMAIL CONFIGURATION
// ==========================================
console.log('📧 On-Premises Exchange Configuration:');

let transporter;
let emailConfigured = false;

/**
 * Configuration logic based on IMAP/SMTP settings.
 * Host: smtp.altitudebpo.co.za
 * Port: 465 (SSL/TLS)
 */
if (process.env.EMAIL_USER && process.env.EMAIL_PASS && 
    (process.env.EMAIL_USER.includes('@altitudebpo.co.za') || process.env.EMAIL_USER.includes('@altitudebpo.com'))) {
  
  console.log('✅ Exchange server credentials found');
  console.log('   Host:', process.env.EMAIL_HOST);
  console.log('   User:', process.env.EMAIL_USER);
  
  const emailConfig = {
    host: process.env.EMAIL_HOST || 'smtp.altitudebpo.co.za',
    port: parseInt(process.env.EMAIL_PORT) || 465,
    secure: process.env.EMAIL_SECURE === 'true', // Should be true for Port 465 per screenshot
    auth: {
      user: process.env.EMAIL_USER,
      pass: process.env.EMAIL_PASS
    },
    tls: {
      rejectUnauthorized: false,  // Essential for internal corporate certificates
      ciphers: 'SSLv3'            // Support for older Exchange protocols if necessary
    }
  };
  
  console.log('   Config:', {
    host: emailConfig.host,
    port: emailConfig.port,
    secure: emailConfig.secure
  });
  
  transporter = nodemailer.createTransport(emailConfig);
  
  // Test the connection to the BPO Mail Server
  transporter.verify(function(error, success) {
    if (error) {
      console.error('❌ Exchange connection failed:', error.message);
      console.log('💡 Troubleshooting per Outlook Settings:');
      console.log('   1. Ensure Port is 465 if SSL/TLS is checked');
      console.log('   2. Verify "My outgoing (SMTP) server requires authentication" is mimicked by the auth object');
      console.log('   3. Check if SPA (Secure Password Authentication) is required by your IT policy');
      console.log('📝 Running in simulation mode for now');
      emailConfigured = false;
    } else {
      console.log('✅ Connected to Altitude BPO Exchange server successfully');
      emailConfigured = true;
    }
  });
  
} else {
  console.log('⚠️  Email credentials not configured or wrong domain');
  console.log('📝 Running in simulation mode');
  console.log('💡 To enable real emails, add to .env:');
  console.log('   EMAIL_USER=samukele.ndlovu@altitudebpo.co.za');
  console.log('   EMAIL_PASS=your-password');
  console.log('   EMAIL_HOST=smtp.altitudebpo.co.za');
  emailConfigured = false;
}


// ==========================================
// MIDDLEWARE CONFIGURATION
// ==========================================
app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// ==========================================
// DATABASE INITIALIZATION
// ==========================================
const db = new Database(path.join(__dirname, 'altitude.db'), { verbose: null });

/**
 * Initializes the SQLite database schema.
 * Defines tables for users, tickets, comments, and security logs.
 */
function initDatabase() {
    console.log('--- Initializing Database Schema ---');

    // Users table: Stores core identity and authentication data
    db.exec(`
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            uuid TEXT UNIQUE NOT NULL,
            name TEXT NOT NULL,
            email TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            role TEXT DEFAULT 'user',
            department TEXT,
            phone TEXT,
            avatar_color TEXT DEFAULT '#007bff',
            is_active INTEGER DEFAULT 1,
            last_login DATETIME,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    `);

    // Tickets table: Core of the helpdesk system
    db.exec(`
        CREATE TABLE IF NOT EXISTS tickets (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            uuid TEXT UNIQUE NOT NULL,
            title TEXT NOT NULL,
            description TEXT NOT NULL,
            status TEXT DEFAULT 'Open',
            priority TEXT DEFAULT 'Medium',
            category TEXT,
            user_id INTEGER,
            assigned_to INTEGER,
            resolved_at DATETIME,
            due_date DATETIME,
            estimated_time INTEGER,
            tags TEXT,
            attachments TEXT,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY(user_id) REFERENCES users(id),
            FOREIGN KEY(assigned_to) REFERENCES users(id)
        )
    `);

    // Comments table: Supports collaboration and audit trails
    db.exec(`
        CREATE TABLE IF NOT EXISTS ticket_comments (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            uuid TEXT UNIQUE NOT NULL,
            ticket_id INTEGER,
            user_id INTEGER,
            message TEXT NOT NULL,
            is_internal INTEGER DEFAULT 0,
            attachments TEXT,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY(ticket_id) REFERENCES tickets(id) ON DELETE CASCADE,
            FOREIGN KEY(user_id) REFERENCES users(id)
        )
    `);

    // Activity log: Essential for enterprise security and Identity Management
    db.exec(`
        CREATE TABLE IF NOT EXISTS activity_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            action TEXT NOT NULL,
            entity_type TEXT,
            entity_id INTEGER,
            details TEXT,
            ip_address TEXT,
            user_agent TEXT,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    `);

    // Identity Provisioning Queue (New for the Identity Manager app)
    db.exec(`
        CREATE TABLE IF NOT EXISTS identity_provisions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            request_uuid TEXT UNIQUE NOT NULL,
            full_name TEXT NOT NULL,
            corporate_email TEXT NOT NULL,
            department TEXT,
            role_profile TEXT,
            status TEXT DEFAULT 'Pending',
            authorized_by INTEGER,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY(authorized_by) REFERENCES users(id)
        )
    `);

    // Create indexes for optimized performance
    db.exec('CREATE INDEX IF NOT EXISTS idx_tickets_status ON tickets(status)');
    db.exec('CREATE INDEX IF NOT EXISTS idx_tickets_user ON tickets(user_id)');
    db.exec('CREATE INDEX IF NOT EXISTS idx_comments_ticket ON ticket_comments(ticket_id)');
    db.exec('CREATE INDEX IF NOT EXISTS idx_identity_email ON identity_provisions(corporate_email)');

    // Run database migrations to ensure all columns exist
    runDatabaseMigrations();

    seedInitialData();
}

/**
 * Run database migrations to add missing columns to existing tables
 */
function runDatabaseMigrations() {
    console.log('--- Running Database Migrations ---');
    
    try {
        // Check if resolved_at column exists in tickets table
        const tableInfo = db.prepare("PRAGMA table_info(tickets)").all();
        const hasResolvedAt = tableInfo.some(column => column.name === 'resolved_at');
        
        if (!hasResolvedAt) {
            console.log('Adding missing column: resolved_at to tickets table');
            db.exec("ALTER TABLE tickets ADD COLUMN resolved_at DATETIME");
            console.log('✅ Added resolved_at column to tickets table');
        }
        
        // Check for other missing columns
        const hasDueDate = tableInfo.some(column => column.name === 'due_date');
        if (!hasDueDate) {
            console.log('Adding missing column: due_date to tickets table');
            db.exec("ALTER TABLE tickets ADD COLUMN due_date DATETIME");
            console.log('✅ Added due_date column to tickets table');
        }
        
        const hasEstimatedTime = tableInfo.some(column => column.name === 'estimated_time');
        if (!hasEstimatedTime) {
            console.log('Adding missing column: estimated_time to tickets table');
            db.exec("ALTER TABLE tickets ADD COLUMN estimated_time INTEGER");
            console.log('✅ Added estimated_time column to tickets table');
        }
        
        const hasTags = tableInfo.some(column => column.name === 'tags');
        if (!hasTags) {
            console.log('Adding missing column: tags to tickets table');
            db.exec("ALTER TABLE tickets ADD COLUMN tags TEXT");
            console.log('✅ Added tags column to tickets table');
        }
        
        const hasAttachments = tableInfo.some(column => column.name === 'attachments');
        if (!hasAttachments) {
            console.log('Adding missing column: attachments to tickets table');
            db.exec("ALTER TABLE tickets ADD COLUMN attachments TEXT");
            console.log('✅ Added attachments column to tickets table');
        }
        
        console.log('✅ Database migrations completed successfully');
        
    } catch (error) {
        console.error('Database migration error:', error);
        // Continue anyway - some columns might already exist
    }
}

/**
 * Populates the system with default accounts if they don't exist.
 */
function seedInitialData() {
    // Admin setup
    const adminExists = db.prepare('SELECT id FROM users WHERE email = ?').get('admin@altitudebpo.com');
    if (!adminExists) {
        const hashedPassword = bcrypt.hashSync('Altitude2026!', 10);
        db.prepare(`
            INSERT INTO users (uuid, name, email, password, role, department, phone, avatar_color)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        `).run(generateUUID(), 'System Administrator', 'admin@altitudebpo.com', hashedPassword, 'it_admin', 'IT Department', '+27 11 123 4567', '#dc3545');
        console.log('✅ Admin user created');
    }

    // Demo user setup
    const userExists = db.prepare('SELECT id FROM users WHERE email = ?').get('user@altitudebpo.com');
    if (!userExists) {
        const hashedPassword = bcrypt.hashSync('password123', 10);
        db.prepare(`
            INSERT INTO users (uuid, name, email, password, role, department, phone, avatar_color)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        `).run(generateUUID(), 'Demo User', 'user@altitudebpo.com', hashedPassword, 'user', 'Sales Department', '+27 11 987 6543', '#28a745');
        console.log('✅ Demo user created');
    }

    // IT Staff setup
    const techExists = db.prepare('SELECT id FROM users WHERE email = ?').get('tech@altitudebpo.com');
    if (!techExists) {
        const hashedPassword = bcrypt.hashSync('Tech2026!', 10);
        db.prepare(`
            INSERT INTO users (uuid, name, email, password, role, department, phone, avatar_color)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        `).run(generateUUID(), 'IT Support Staff', 'tech@altitudebpo.com', hashedPassword, 'it_admin', 'IT Department', '+27 11 555 1234', '#3B82F6');
        console.log('✅ IT Staff user created');
    }
}

function addDeviceColumnsToTickets() {
  try {
    // Check if device_name column exists
    const tableInfo = db.prepare("PRAGMA table_info(tickets)").all();
    
    // Add device_name if it doesn't exist
    const hasDeviceName = tableInfo.some(column => column.name === 'device_name');
    if (!hasDeviceName) {
      console.log('Adding device_name column to tickets table');
      db.exec("ALTER TABLE tickets ADD COLUMN device_name TEXT");
    }
    
    // Add device_brand if it doesn't exist
    const hasDeviceBrand = tableInfo.some(column => column.name === 'device_brand');
    if (!hasDeviceBrand) {
      console.log('Adding device_brand column to tickets table');
      db.exec("ALTER TABLE tickets ADD COLUMN device_brand TEXT");
    }
    
    // Add device_period if it doesn't exist
    const hasDevicePeriod = tableInfo.some(column => column.name === 'device_period');
    if (!hasDevicePeriod) {
      console.log('Adding device_period column to tickets table');
      db.exec("ALTER TABLE tickets ADD COLUMN device_period TEXT");
    }
    
    console.log('✅ Device columns added to tickets table');
    
  } catch (error) {
    console.error('Error adding device columns:', error);
  }
}

// Call this function in your initDatabase() function:
function initDatabase() {
  // ... existing code ...
  
  runDatabaseMigrations();
  addDeviceColumnsToTickets(); // Add this line
  seedInitialData();
}

// ==========================================
// UTILITY FUNCTIONS
// ==========================================
// Function to update stale tickets (call this periodically)
function updateStaleTickets() {
    try {
        const staleDate = new Date();
        staleDate.setDate(staleDate.getDate() - 7); // 7 days old
        
        const result = db.prepare(`
            UPDATE tickets 
            SET status = 'Closed',
                updated_at = CURRENT_TIMESTAMP
            WHERE status = 'Open' 
            AND created_at < ?
            AND due_date < CURRENT_TIMESTAMP
        `).run(staleDate.toISOString());

        if (result.changes > 0) {
            console.log(`Auto-closed ${result.changes} stale tickets`);
            logActivity(1, 'SYSTEM_AUTO_CLOSE', 'ticket', null, `Auto-closed ${result.changes} stale tickets`);
        }
    } catch (error) {
        console.error('Auto-close error:', error);
    }
}

// Call this function periodically (e.g., once a day)
setInterval(updateStaleTickets, 24 * 60 * 60 * 1000); // Every 24 hours


function generateUUID() {
    return 'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g, function(c) {
        const r = Math.random() * 16 | 0;
        const v = c === 'x' ? r : (r & 0x3 | 0x8);
        return v.toString(16);
    });
}

function logActivity(userId, action, entityType = null, entityId = null, details = null, req = null) {
    try {
        db.prepare(`
            INSERT INTO activity_log (user_id, action, entity_type, entity_id, details, ip_address, user_agent)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        `).run(userId, action, entityType, entityId, details, req?.ip || '127.0.0.1', req?.headers['user-agent']);
    } catch (error) {
        console.error('Activity log error:', error);
    }
}

// ==========================================
// AUTHENTICATION MIDDLEWARE
// ==========================================

const authenticateToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    if (!token) return res.status(401).json({ error: 'Authentication token required' });

    jwt.verify(token, SECRET_KEY, (err, user) => {
        if (err) return res.status(403).json({ error: 'Invalid or expired token' });
        req.user = user;
        next();
    });
};

const isAdmin = (req, res, next) => {
    if (req.user.role !== 'it_admin') return res.status(403).json({ error: 'Admin access required' });
    next();
};

// ==========================================
// API ROUTES: CORE SYSTEM
// ==========================================

// Health check endpoint
app.get('/api/health', (req, res) => {
    res.json({ 
        status: 'healthy', 
        timestamp: new Date().toISOString(),
        version: '2.0.1'
    });
});

// ==========================================
// API ROUTES: DASHBOARD & ANALYTICS - FIXED VERSION
// ==========================================

app.get('/api/dashboard/stats', authenticateToken, (req, res) => {
    try {
        console.log(`GET /api/dashboard/stats called by user ${req.user.id} (role: ${req.user.role})`);
        
        // Get ticket statistics with proper status filtering
        const whereClause = req.user.role === 'it_admin' ? '' : 'WHERE user_id = ' + req.user.id;
        
        // First, check if there are any tickets
        const totalTickets = db.prepare(`SELECT COUNT(*) as count FROM tickets ${whereClause}`).get();
        
        console.log(`Total tickets found: ${totalTickets.count}`);
        
        // Initialize stats with zeros
        const stats = {
            total: 0,
            open: 0,
            in_progress: 0,
            resolved: 0,
            closed: 0,
            critical: 0,
            high: 0,
            medium: 0,
            low: 0
        };
        
        if (totalTickets.count > 0) {
            // Only run the full query if there are tickets
            const statsResult = db.prepare(`
                SELECT 
                    COUNT(*) as total,
                    SUM(CASE WHEN status = 'Open' THEN 1 ELSE 0 END) as open,
                    SUM(CASE WHEN status = 'In Progress' THEN 1 ELSE 0 END) as in_progress,
                    SUM(CASE WHEN status = 'Resolved' THEN 1 ELSE 0 END) as resolved,
                    SUM(CASE WHEN status = 'Closed' THEN 1 ELSE 0 END) as closed,
                    SUM(CASE WHEN priority = 'Critical' THEN 1 ELSE 0 END) as critical,
                    SUM(CASE WHEN priority = 'High' THEN 1 ELSE 0 END) as high,
                    SUM(CASE WHEN priority = 'Medium' THEN 1 ELSE 0 END) as medium,
                    SUM(CASE WHEN priority = 'Low' THEN 1 ELSE 0 END) as low
                FROM tickets
                ${whereClause}
            `).get();
            
            // Convert null values to 0
            if (statsResult) {
                stats.total = statsResult.total || 0;
                stats.open = statsResult.open || 0;
                stats.in_progress = statsResult.in_progress || 0;
                stats.resolved = statsResult.resolved || 0;
                stats.closed = statsResult.closed || 0;
                stats.critical = statsResult.critical || 0;
                stats.high = statsResult.high || 0;
                stats.medium = statsResult.medium || 0;
                stats.low = statsResult.low || 0;
            }
        }
        
        console.log('Stats calculated:', stats);

        // Get recent tickets for dashboard
        const recentQuery = `
            SELECT t.*, u.name as requester_name, u.avatar_color as requester_avatar
            FROM tickets t
            LEFT JOIN users u ON t.user_id = u.id
            ${whereClause ? whereClause.replace('user_id', 't.user_id') : ''}
            ORDER BY t.created_at DESC 
            LIMIT 10
        `;
        
        const recentTickets = db.prepare(recentQuery).all();
        console.log(`Recent tickets found: ${recentTickets.length}`);

        // Get recent activity
        let recentActivity = [];
        try {
            const activityQuery = req.user.role === 'it_admin' 
                ? 'SELECT a.*, u.name as user_name FROM activity_log a JOIN users u ON a.user_id = u.id ORDER BY a.created_at DESC LIMIT 10'
                : 'SELECT a.*, u.name as user_name FROM activity_log a JOIN users u ON a.user_id = u.id WHERE a.user_id = ? OR a.entity_id = ? ORDER BY a.created_at DESC LIMIT 10';
            
            const activityParams = req.user.role === 'it_admin' ? [] : [req.user.id, req.user.id];
            recentActivity = db.prepare(activityQuery).all(...activityParams);
        } catch (activityError) {
            console.error('Activity log fetch error:', activityError);
            // Continue without activity data
        }

        // Get performance metrics (only if there are resolved tickets)
        let avgResolutionTime = 0;
        if (stats.resolved > 0) {
            try {
                const performance = db.prepare(`
                    SELECT 
                        AVG(CASE WHEN status = 'Resolved' AND resolved_at IS NOT NULL THEN 
                            CAST(julianday(resolved_at) - julianday(created_at) AS INTEGER) 
                        END) as avg_resolution_time_days
                    FROM tickets
                    WHERE status = 'Resolved'
                    ${req.user.role === 'it_admin' ? '' : 'AND user_id = ' + req.user.id}
                `).get();
                
                avgResolutionTime = performance.avg_resolution_time_days ? Math.round(performance.avg_resolution_time_days * 100) / 100 : 0;
            } catch (perfError) {
                console.error('Performance metrics error:', perfError);
            }
        }

        res.json({ 
            stats, 
            recentTickets, 
            recentActivity,
            performance: {
                avg_resolution_time_days: avgResolutionTime
            }
        });
    } catch (error) {
        console.error('Dashboard stats error:', error);
        console.error('Error stack:', error.stack);
        res.status(500).json({ 
            error: 'Internal server error',
            message: error.message,
            details: 'Check server logs for more information'
        });
    }
});

// Get ticket status summary - FIXED VERSION
app.get('/api/tickets/status/summary', authenticateToken, (req, res) => {
    try {
        const whereClause = req.user.role === 'it_admin' ? '' : 'WHERE user_id = ' + req.user.id;
        
        // First check total count
        const totalResult = db.prepare(`SELECT COUNT(*) as total FROM tickets ${whereClause}`).get();
        const totalCount = totalResult.total || 0;
        
        let summary = [];
        if (totalCount > 0) {
            summary = db.prepare(`
                SELECT 
                    status,
                    COUNT(*) as count,
                    ROUND(COUNT(*) * 100.0 / ${totalCount}, 1) as percentage
                FROM tickets
                ${whereClause}
                GROUP BY status
                ORDER BY 
                    CASE status 
                        WHEN 'Open' THEN 1
                        WHEN 'In Progress' THEN 2
                        WHEN 'Resolved' THEN 3
                        WHEN 'Closed' THEN 4
                        ELSE 5
                    END
            `).all();
        }

        res.json({ summary });
    } catch (error) {
        console.error('Status summary error:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

// LOGIN
app.post('/api/auth/login', async (req, res) => {
    try {
        const { email, password } = req.body;
        if (!email || !password) return res.status(400).json({ error: 'Email and password are required' });

        const user = db.prepare('SELECT * FROM users WHERE email = ? AND is_active = 1').get(email);
        if (!user || !(await bcrypt.compare(password, user.password))) {
            return res.status(401).json({ error: 'Invalid credentials' });
        }

        db.prepare('UPDATE users SET last_login = CURRENT_TIMESTAMP WHERE id = ?').run(user.id);

        const token = jwt.sign(
            { id: user.id, uuid: user.uuid, name: user.name, email: user.email, role: user.role, department: user.department, avatar_color: user.avatar_color },
            SECRET_KEY, { expiresIn: '24h' }
        );

        const { password: _, ...userWithoutPassword } = user;
        logActivity(user.id, 'USER_LOGIN', 'user', user.id, 'User logged in', req);
        res.json({ token, user: userWithoutPassword });
    } catch (error) {
        res.status(500).json({ error: 'Internal server error' });
    }
});

// ==========================================
// API ROUTES: IDENTITY MANAGEMENT (NEW)
// ==========================================

/**
 * Provision New Enterprise Identity
 * This route handles the request from the "Authorize Identity" popup.
 */
app.post('/api/identity/provision', authenticateToken, async (req, res) => {
    try {
        const { full_name, corporate_email, department, role_profile, temporary_access_key } = req.body;

        // 1. Validation Logic
        if (!full_name || !corporate_email) {
            return res.status(400).json({ error: 'Critical: Full name and Email are required for provisioning.' });
        }

        // Domain Check: Ensure the email belongs to the corporate domain
        if (!corporate_email.endsWith('@altitudebpo.co.za') && !corporate_email.endsWith('@altitudebpo.com')) {
            return res.status(400).json({ error: 'Critical: Identity must use a valid corporate domain.' });
        }

        // 2. Check for duplicates
        const existing = db.prepare('SELECT id FROM users WHERE email = ?').get(corporate_email);
        if (existing) {
            return res.status(400).json({ error: 'Critical: Identity already exists in the system.' });
        }

        // 3. Process Provisioning
        const hashedPassword = await bcrypt.hash(temporary_access_key || 'Default2026!', 10);
        const userUuid = generateUUID();

        // Transactional insert to ensure data integrity
        const info = db.transaction(() => {
            const result = db.prepare(`
                INSERT INTO users (uuid, name, email, password, role, department, avatar_color)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            `).run(
                userUuid, 
                full_name, 
                corporate_email, 
                hashedPassword, 
                role_profile === 'Standard User' ? 'user' : 'it_admin',
                department,
                '#5f6368'
            );

            db.prepare(`
                INSERT INTO identity_provisions (request_uuid, full_name, corporate_email, department, role_profile, status, authorized_by)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            `).run(generateUUID(), full_name, corporate_email, department, role_profile, 'Completed', req.user.id);

            return result;
        })();

        logActivity(req.user.id, 'IDENTITY_PROVISIONED', 'user', info.lastInsertRowid, `Provisioned: ${corporate_email}`, req);

        res.status(201).json({
            success: true,
            message: 'New Enterprise Identity successfully provisioned.',
            identity_id: userUuid
        });

    } catch (error) {
        console.error('Provisioning Error:', error);
        res.status(500).json({ error: 'Critical: Could not provision new identity due to a server error.' });
    }
});

app.get('/api/admin/users', authenticateToken, isAdmin, (req, res) => {
    try {
        console.log('Fetching all users for Identity Manager...');
        
        const users = db.prepare(`
            SELECT 
                id, uuid, name, email, role, department, 
                avatar_color, is_active, last_login, created_at
            FROM users 
            ORDER BY created_at DESC
        `).all();
        
        console.log(`Found ${users.length} users`);
        res.json(users);
    } catch (error) {
        console.error('Error fetching users:', error);
        res.status(500).json({ error: 'Internal server error while fetching users' });
    }
});

// ==========================================
// API ROUTES: TICKETING SYSTEM
// ==========================================

// Get all tickets with advanced filtering
app.get('/api/tickets', authenticateToken, (req, res) => {
    try {
        let query = `
            SELECT t.*, 
                   u.name as requester_name, u.email as requester_email, u.avatar_color as requester_avatar,
                   a.name as assigned_name, a.avatar_color as assigned_avatar,
                   (SELECT COUNT(*) FROM ticket_comments WHERE ticket_id = t.id) as comment_count
            FROM tickets t
            LEFT JOIN users u ON t.user_id = u.id
            LEFT JOIN users a ON t.assigned_to = a.id
        `;
        let params = [];

        if (req.user.role !== 'it_admin') {
            query += ' WHERE t.user_id = ?';
            params.push(req.user.id);
        } else {
            query += ' WHERE 1=1';
        }

        // Status filter
        if (req.query.status && req.query.status !== 'all') {
            query += ' AND t.status = ?';
            params.push(req.query.status);
        }

        query += ' ORDER BY t.created_at DESC';
        const tickets = db.prepare(query).all(...params);
        res.json(tickets);
    } catch (error) {
        res.status(500).json({ error: 'Internal server error' });
    }
});

// Single ticket view - FIXED VERSION
app.get('/api/tickets/:id', authenticateToken, (req, res) => {
    try {
        console.log(`GET /api/tickets/${req.params.id} called by user ${req.user.id}`);
        
        // Try to parse as integer (ticket ID)
        const ticketId = parseInt(req.params.id);
        if (isNaN(ticketId)) {
            return res.status(400).json({ error: 'Invalid ticket ID' });
        }

        const ticket = db.prepare(`
            SELECT t.*, 
                   u.name as requester_name, u.email as requester_email, u.department as requester_dept,
                   u.avatar_color as requester_avatar,
                   a.name as assigned_name, a.email as assigned_email
            FROM tickets t
            LEFT JOIN users u ON t.user_id = u.id
            LEFT JOIN users a ON t.assigned_to = a.id
            WHERE t.id = ?
        `).get(ticketId);

        console.log('Ticket found:', ticket ? 'Yes' : 'No');
        
        if (!ticket) {
            console.log(`Ticket ID ${ticketId} not found in database`);
            return res.status(404).json({ 
                error: 'Ticket not found',
                details: `Ticket with ID ${ticketId} does not exist in the database`
            });
        }

        // Check permissions (admin or ticket owner)
        if (req.user.role !== 'it_admin' && ticket.user_id !== req.user.id) {
            console.log(`Access denied: User ${req.user.id} trying to access ticket ${ticketId} owned by ${ticket.user_id}`);
            return res.status(403).json({ 
                error: 'Access denied',
                details: 'You do not have permission to view this ticket'
            });
        }

        console.log(`Returning ticket ${ticketId} to user ${req.user.id}`);
        res.json(ticket);
    } catch (error) {
        console.error('Ticket fetch error:', error);
        res.status(500).json({ 
            error: 'Internal server error',
            details: error.message 
        });
    }
});

// Ticket creation
app.post('/api/tickets', authenticateToken, (req, res) => {
  try {
    const { title, description, priority, category, device_name, device_brand, device_period } = req.body;
    if (!title || !description) return res.status(400).json({ error: 'Title and description are required' });

    const dueDate = new Date();
    dueDate.setDate(dueDate.getDate() + (priority === 'Critical' ? 1 : 7));

    // Add new columns for device information
    const result = db.prepare(`
      INSERT INTO tickets (
        uuid, title, description, priority, category, 
        user_id, due_date, tags, 
        device_name, device_brand, device_period,  -- New columns
        created_at, updated_at
      )
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
    `).run(
      generateUUID(), 
      title, 
      description, 
      priority || 'Medium', 
      category || 'General', 
      req.user.id, 
      dueDate.toISOString(),
      category === 'Resignation' ? 'Resignation-Device-Return' : '',  // Simplified tags
      device_name || null,
      device_brand || null,
      device_period || null
    );

    // Log the activity
    logActivity(req.user.id, 'TICKET_CREATED', 'ticket', result.lastInsertRowid, `Created ticket: ${title}`, req);

    // Return the created ticket with all fields
    const newTicket = db.prepare(`
      SELECT t.*, u.name as requester_name, u.email as requester_email, u.avatar_color as requester_avatar
      FROM tickets t
      JOIN users u ON t.user_id = u.id
      WHERE t.id = ?
    `).get(result.lastInsertRowid);

    res.status(201).json({ 
      success: true, 
      ticket: newTicket,
      message: 'Ticket created successfully'
    });
  } catch (error) {
    console.error('Ticket creation error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});
// ==========================================
// API ROUTES: COMMENTS
// ==========================================

// GET Ticket Comments
app.get('/api/tickets/:id/comments', authenticateToken, (req, res) => {
    try {
        console.log(`GET /api/tickets/${req.params.id}/comments called`);
        
        const ticketId = parseInt(req.params.id);
        if (isNaN(ticketId)) {
            return res.status(400).json({ error: 'Invalid ticket ID' });
        }

        // First check if ticket exists
        const ticketExists = db.prepare('SELECT id FROM tickets WHERE id = ?').get(ticketId);
        if (!ticketExists) {
            return res.status(404).json({ error: 'Ticket not found' });
        }

        // Check permissions
        if (req.user.role !== 'it_admin') {
            const ticket = db.prepare('SELECT user_id FROM tickets WHERE id = ?').get(ticketId);
            if (ticket.user_id !== req.user.id) {
                return res.status(403).json({ error: 'Access denied' });
            }
        }

        const comments = db.prepare(`
            SELECT tc.*, u.name as user_name, u.role as user_role, u.avatar_color as user_avatar
            FROM ticket_comments tc
            JOIN users u ON tc.user_id = u.id
            WHERE tc.ticket_id = ? 
            ORDER BY tc.created_at ASC
        `).all(ticketId);
        
        res.json(comments);
    } catch (error) {
        console.error('Comments fetch error:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

// POST Ticket Comments - FIXED VERSION
app.post('/api/tickets/:id/comments', authenticateToken, (req, res) => {
    try {
        console.log(`POST /api/tickets/${req.params.id}/comments called`);
        console.log('Request body:', req.body);
        
        const ticketId = parseInt(req.params.id);
        if (isNaN(ticketId)) {
            return res.status(400).json({ error: 'Invalid ticket ID' });
        }

        const { content, message } = req.body;
        const commentText = content || message;
        
        if (!commentText || commentText.trim() === '') {
            return res.status(400).json({ error: 'Comment content required' });
        }

        // First check if ticket exists
        const ticketExists = db.prepare('SELECT id, user_id FROM tickets WHERE id = ?').get(ticketId);
        if (!ticketExists) {
            return res.status(404).json({ error: 'Ticket not found' });
        }

        // Check permissions
        if (req.user.role !== 'it_admin' && ticketExists.user_id !== req.user.id) {
            return res.status(403).json({ error: 'Access denied' });
        }

        const result = db.prepare(`
            INSERT INTO ticket_comments (uuid, ticket_id, user_id, message, created_at, updated_at)
            VALUES (?, ?, ?, ?, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
        `).run(generateUUID(), ticketId, req.user.id, commentText.trim());
        
        // Get the newly created comment with user info
        const newComment = db.prepare(`
            SELECT tc.*, u.name as user_name, u.role as user_role, u.avatar_color as user_avatar
            FROM ticket_comments tc
            JOIN users u ON tc.user_id = u.id
            WHERE tc.id = ?
        `).get(result.lastInsertRowid);
        
        // Log activity
        logActivity(req.user.id, 'COMMENT_ADDED', 'ticket_comment', ticketId, `Added comment to ticket ${ticketId}`, req);
        
        res.status(201).json({ 
            success: true, 
            comment: newComment,
            message: 'Comment added successfully'
        });
    } catch (error) {
        console.error('Comment creation error:', error);
        res.status(500).json({ error: 'Internal server error: ' + error.message });
    }
});

// ==========================================
// API ROUTES: TICKET FORWARDING WITH EMAIL
// ==========================================

app.post('/api/tickets/:id/forward', authenticateToken, async (req, res) => {
  try {
    console.log(`POST /api/tickets/${req.params.id}/forward called`);
    
    const ticketId = parseInt(req.params.id);
    if (isNaN(ticketId)) {
      return res.status(400).json({ error: 'Invalid ticket ID' });
    }

    const { email, message, forwarded_by } = req.body;
    
    if (!email || !email.trim()) {
      return res.status(400).json({ error: 'Recipient email is required' });
    }

    // Get ticket details
    const ticket = db.prepare(`
      SELECT t.*, u.name as requester_name, u.email as requester_email
      FROM tickets t
      LEFT JOIN users u ON t.user_id = u.id
      WHERE t.id = ?
    `).get(ticketId);

    if (!ticket) {
      return res.status(404).json({ error: 'Ticket not found' });
    }

    // Check permissions - only admin or ticket owner can forward
    if (req.user.role !== 'it_admin' && ticket.user_id !== req.user.id) {
      return res.status(403).json({ error: 'Access denied' });
    }

    // Check if email credentials are configured
    const hasEmailConfig = process.env.EMAIL_USER && 
                          process.env.EMAIL_PASS &&
                          process.env.EMAIL_USER !== 'your-email@gmail.com';

    if (!hasEmailConfig) {
      console.log(`📝 Email simulation mode - No email credentials configured`);
      
      // Log the activity
      logActivity(req.user.id, 'TICKET_FORWARDED', 'ticket', ticketId, 
        `Simulated forwarding to ${email}`, req);
      
      // Add a comment to the ticket about forwarding
      const forwardComment = `Ticket forwarded to ${email} by ${req.user.name}. ${message ? `Note: ${message}` : ''} [EMAIL SIMULATION MODE]`;
      
      db.prepare(`
        INSERT INTO ticket_comments (uuid, ticket_id, user_id, message, is_internal, created_at, updated_at)
        VALUES (?, ?, ?, ?, 1, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
      `).run(generateUUID(), ticketId, req.user.id, forwardComment);
      
      return res.json({
        success: true,
        message: `Ticket forwarding logged for ${email}. Configure email in .env file to send actual emails.`,
        emailSent: false,
        simulation: true
      });
    }

    // Prepare email content
    const emailSubject = `[Ticket #INC-${ticketId}] Forwarded: ${ticket.title}`;
    
    const emailBody = `
      <!DOCTYPE html>
      <html>
      <head>
        <style>
          body { font-family: Arial, sans-serif; line-height: 1.6; color: #333; }
          .container { max-width: 600px; margin: 0 auto; padding: 20px; }
          .header { background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 20px; border-radius: 10px 10px 0 0; }
          .content { background: #f9f9f9; padding: 20px; border-radius: 0 0 10px 10px; }
          .ticket-info { background: white; padding: 15px; border-left: 4px solid #667eea; margin: 15px 0; }
          .footer { margin-top: 20px; padding-top: 20px; border-top: 1px solid #ddd; color: #666; font-size: 12px; }
        </style>
      </head>
      <body>
        <div class="container">
          <div class="header">
            <h1>📧 Ticket Forwarded</h1>
            <p>Altitude BPO Internal Ticketing System</p>
          </div>
          <div class="content">
            <p>Hello,</p>
            
            <p>A ticket has been forwarded to you for attention:</p>
            
            <div class="ticket-info">
              <h3>Ticket #INC-${ticketId}: ${ticket.title}</h3>
              <p><strong>Category:</strong> ${ticket.category || 'Not specified'}</p>
              <p><strong>Priority:</strong> ${ticket.priority || 'Medium'}</p>
              <p><strong>Status:</strong> ${ticket.status || 'Open'}</p>
              <p><strong>Submitted by:</strong> ${ticket.requester_name} (${ticket.requester_email})</p>
              <p><strong>Submitted on:</strong> ${new Date(ticket.created_at).toLocaleString()}</p>
              <p><strong>Forwarded by:</strong> ${forwarded_by || req.user.name}</p>
            </div>
            
            ${message ? `<p><strong>Additional Message:</strong><br>${message}</p>` : ''}
            
            <p><strong>Ticket Description:</strong><br>${ticket.description}</p>
          </div>
          <div class="footer">
            <p>This is an automated message from Altitude BPO Ticketing System.</p>
          </div>
        </div>
      </body>
      </html>
    `;

    // Prepare text version for email clients
    const textVersion = `
      TICKET FORWARDED: #INC-${ticketId} - ${ticket.title}
      
      A support ticket has been forwarded to you by ${forwarded_by || req.user.name}.
      
      TICKET DETAILS:
      --------------
      ID: INC-${ticketId}
      Title: ${ticket.title}
      Category: ${ticket.category || 'Not specified'}
      Priority: ${ticket.priority || 'Medium'}
      Status: ${ticket.status || 'Open'}
      Submitted by: ${ticket.requester_name}
      Submitted on: ${new Date(ticket.created_at).toLocaleString()}
      
      DESCRIPTION:
      ${ticket.description}
      
      ${message ? `FORWARDING NOTE: ${message}\n\n` : ''}
      
      ACTION REQUIRED:
      Please review this ticket and take appropriate action.
      
      View ticket online: http://localhost:3000/#/tickets/${ticketId}
      
      ---
      Altitude BPO Internal Ticketing System
      This is an automated message. Do not reply to this email.
    `;

    // Email configuration
    const mailOptions = {
      from: `"${process.env.EMAIL_FROM_NAME || 'Altitude BPO Ticketing'}" <${process.env.EMAIL_FROM_ADDRESS || process.env.EMAIL_USER}>`,
      to: email,
      subject: emailSubject,
      html: emailBody,
      text: textVersion,  // ← Now it's defined!
      headers: {
        'X-Priority': '1',
        'X-MSMail-Priority': 'High',
        'Importance': 'high'
      }
    };


    // Send email
    try {
      const emailResult = await transporter.sendMail(mailOptions);
      console.log('Email sent successfully:', emailResult.messageId);
      
      // Log the forwarding activity
      logActivity(req.user.id, 'TICKET_FORWARDED', 'ticket', ticketId, 
        `Forwarded ticket to ${email}`, req);
      
      // Add a comment to the ticket about forwarding
      const forwardComment = `Ticket forwarded to ${email} by ${req.user.name}. ${message ? `Note: ${message}` : ''}`;
      
      db.prepare(`
        INSERT INTO ticket_comments (uuid, ticket_id, user_id, message, is_internal, created_at, updated_at)
        VALUES (?, ?, ?, ?, 1, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
      `).run(generateUUID(), ticketId, req.user.id, forwardComment);
      
      return res.json({
        success: true,
        message: `Ticket forwarded to ${email} successfully`,
        emailSent: true,
        emailId: emailResult.messageId
      });
      
    } catch (emailError) {
      console.error('Email sending failed:', emailError);
      
      // Even if email fails, log the forwarding attempt
      logActivity(req.user.id, 'TICKET_FORWARD_ATTEMPTED', 'ticket', ticketId, 
        `Failed to forward ticket to ${email}: ${emailError.message}`, req);
      
      return res.status(500).json({
        success: false,
        message: `Ticket forwarding logged but email failed to send: ${emailError.message}`,
        emailSent: false,
        error: process.env.NODE_ENV === 'development' ? emailError.message : 'Email service error'
      });
    }

  } catch (error) {
    console.error('Ticket forwarding error:', error);
    return res.status(500).json({ 
      error: 'Internal server error',
      details: error.message 
    });
  }
});


// ==========================================
// API ROUTES: TICKET STATUS MANAGEMENT - FIXED VERSION
// ==========================================

// Update ticket status (for resolving/closing) - FIXED VERSION
app.put('/api/tickets/:id', authenticateToken, (req, res) => {
    try {
        console.log(`\n=== PUT /api/tickets/${req.params.id} called ===`);
        console.log('User:', req.user.id, req.user.name, req.user.role);
        console.log('Request body:', req.body);
        
        const ticketId = parseInt(req.params.id);
        if (isNaN(ticketId)) {
            console.log('Invalid ticket ID:', req.params.id);
            return res.status(400).json({ error: 'Invalid ticket ID' });
        }

        const { status, resolution_note } = req.body;
        
        // Validate status
        const validStatuses = ['Open', 'In Progress', 'Resolved', 'Closed'];
        if (status && !validStatuses.includes(status)) {
            console.log('Invalid status:', status);
            return res.status(400).json({ 
                error: 'Invalid status', 
                validStatuses: validStatuses 
            });
        }

        // Check if ticket exists
        const ticket = db.prepare('SELECT * FROM tickets WHERE id = ?').get(ticketId);
        console.log('Ticket found in DB:', ticket ? 'Yes' : 'No');
        
        if (!ticket) {
            console.log(`Ticket ID ${ticketId} not found in database`);
            // Check what tickets exist in database
            const allTickets = db.prepare('SELECT id, title FROM tickets ORDER BY id DESC LIMIT 10').all();
            console.log('Available tickets (last 10):', allTickets);
            
            return res.status(404).json({ 
                error: 'Ticket not found',
                availableTickets: allTickets,
                message: `Ticket with ID ${ticketId} does not exist in the database`
            });
        }

        console.log('Ticket details:', {
            id: ticket.id,
            title: ticket.title,
            status: ticket.status,
            user_id: ticket.user_id,
            assigned_to: ticket.assigned_to
        });

        // Check permissions (admin or ticket owner)
        if (req.user.role !== 'it_admin' && ticket.user_id !== req.user.id) {
            console.log(`Permission denied: User ${req.user.id} cannot modify ticket ${ticketId} (owner: ${ticket.user_id})`);
            return res.status(403).json({ 
                error: 'Access denied',
                message: 'Only ticket owner or administrator can modify tickets'
            });
        }

        // Update ticket status
        const updateFields = ['updated_at = CURRENT_TIMESTAMP'];
        const updateParams = [];
        
        if (status) {
            updateFields.push('status = ?');
            updateParams.push(status);
            
            // Set resolved_at if status is Resolved or Closed
            if (status === 'Resolved' || status === 'Closed') {
                updateFields.push('resolved_at = CURRENT_TIMESTAMP');
            }
        }
        
        updateParams.push(ticketId);
        
        const updateQuery = `UPDATE tickets SET ${updateFields.join(', ')} WHERE id = ?`;
        console.log('Update query:', updateQuery);
        console.log('Update params:', updateParams);
        
        const result = db.prepare(updateQuery).run(...updateParams);
        console.log('Rows affected:', result.changes);
        
        // Log the activity
        const action = status === 'Resolved' ? 'TICKET_RESOLVED' : 
                      status === 'Closed' ? 'TICKET_CLOSED' : 'TICKET_UPDATED';
        
        logActivity(req.user.id, action, 'ticket', ticketId, `Status changed to ${status}`, req);
        
        // Add resolution comment if provided
        if (resolution_note && resolution_note.trim() !== '') {
            const commentUuid = generateUUID();
            const commentMessage = status === 'Resolved' || status === 'Closed' 
                ? `Ticket ${status.toLowerCase()}: ${resolution_note}`
                : `Status updated to ${status}: ${resolution_note}`;
            
            db.prepare(`
                INSERT INTO ticket_comments (uuid, ticket_id, user_id, message, is_internal, created_at, updated_at)
                VALUES (?, ?, ?, ?, 1, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
            `).run(commentUuid, ticketId, req.user.id, commentMessage.trim());
            
            console.log('Added resolution comment');
            logActivity(req.user.id, 'COMMENT_ADDED', 'ticket_comment', ticketId, 'Added resolution comment', req);
        }
        
        // Get updated ticket with user info
        const updatedTicket = db.prepare(`
            SELECT t.*, 
                   u.name as requester_name, u.email as requester_email, 
                   u.department as requester_dept, u.avatar_color as requester_avatar,
                   a.name as assigned_name, a.email as assigned_email
            FROM tickets t
            LEFT JOIN users u ON t.user_id = u.id
            LEFT JOIN users a ON t.assigned_to = a.id
            WHERE t.id = ?
        `).get(ticketId);
        
        console.log('Ticket updated successfully');
        console.log('New status:', updatedTicket.status);
        console.log('========================================\n');
        
        res.json({ 
            success: true, 
            message: `Ticket ${status ? status.toLowerCase() : 'updated'} successfully`,
            status: status,
            ticket: updatedTicket,
            changes: result.changes
        });
        
    } catch (error) {
        console.error('Ticket update error:', error);
        console.error('Error stack:', error.stack);
        res.status(500).json({ 
            error: 'Internal server error',
            message: error.message,
            stack: process.env.NODE_ENV === 'development' ? error.stack : undefined
        });
    }
});

// Alternative endpoint for resolving tickets (for frontend compatibility)
app.put('/api/tickets/:id/resolve', authenticateToken, (req, res) => {
    try {
        console.log(`\n=== PUT /api/tickets/${req.params.id}/resolve called ===`);
        
        const ticketId = parseInt(req.params.id);
        if (isNaN(ticketId)) {
            return res.status(400).json({ error: 'Invalid ticket ID' });
        }

        const { resolution_note } = req.body;
        
        // Check if ticket exists
        const ticket = db.prepare('SELECT * FROM tickets WHERE id = ?').get(ticketId);
        if (!ticket) {
            return res.status(404).json({ error: 'Ticket not found' });
        }

        // Check permissions - Allow IT admins OR ticket owners
        if (req.user.role !== 'it_admin' && ticket.user_id !== req.user.id) {
            console.log(`Permission denied: User ${req.user.id} cannot modify ticket ${ticketId} (owner: ${ticket.user_id})`);
            return res.status(403).json({ 
                error: 'Access denied',
                message: 'Only ticket owner or administrator can modify tickets'
            });
        }
        
        // Update ticket to Resolved status
        const result = db.prepare(`
            UPDATE tickets 
            SET status = 'Resolved', 
                resolved_at = CURRENT_TIMESTAMP, 
                updated_at = CURRENT_TIMESTAMP 
            WHERE id = ?
        `).run(ticketId);
        
        console.log(`Ticket ${ticketId} resolved, rows affected: ${result.changes}`);
        
        // Add resolution comment if provided
        if (resolution_note && resolution_note.trim() !== '') {
            db.prepare(`
                INSERT INTO ticket_comments (uuid, ticket_id, user_id, message, is_internal, created_at, updated_at)
                VALUES (?, ?, ?, ?, 1, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
            `).run(generateUUID(), ticketId, req.user.id, `Ticket resolved: ${resolution_note}`);
        }
        
        logActivity(req.user.id, 'TICKET_RESOLVED', 'ticket', ticketId, 'Resolved ticket', req);
        
        res.json({ 
            success: true, 
            message: 'Ticket resolved successfully',
            resolved_at: new Date().toISOString(),
            changes: result.changes
        });
        
    } catch (error) {
        console.error('Resolve ticket error:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

// Close ticket with resolution
app.put('/api/tickets/:id/close', authenticateToken, (req, res) => {
    try {
        const { resolution_note } = req.body;
        if (!resolution_note) return res.status(400).json({ error: 'Resolution note required' });
        
        // Check if ticket exists and user has permission
        const ticket = db.prepare('SELECT * FROM tickets WHERE id = ?').get(req.params.id);
        if (!ticket) {
            return res.status(404).json({ error: 'Ticket not found' });
        }

        if (req.user.role !== 'it_admin') {
            return res.status(403).json({ error: 'Admin access required to close tickets' });
        }
        
        // Update ticket to Closed status
        db.prepare('UPDATE tickets SET status = "Closed", updated_at = CURRENT_TIMESTAMP WHERE id = ?').run(req.params.id);
        
        // Add resolution as comment
        const commentUuid = generateUUID();
        db.prepare(`
            INSERT INTO ticket_comments (uuid, ticket_id, user_id, message, is_internal)
            VALUES (?, ?, ?, ?, 1)
        `).run(commentUuid, req.params.id, req.user.id, `Ticket closed: ${resolution_note}`);
        
        logActivity(req.user.id, 'TICKET_CLOSED', 'ticket', req.params.id, `Closed ticket with note: ${resolution_note}`, req);
        
        res.json({ success: true, message: 'Ticket closed successfully' });
        
    } catch (error) {
        console.error('Close ticket error:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

// ==========================================
// API ROUTES: DASHBOARD & ANALYTICS
// ==========================================

// Note: This is a duplicate route - removed to avoid conflict

// Get ticket status summary
// Note: This is a duplicate route - removed to avoid conflict

// ==========================================
// DEBUG ENDPOINTS (for troubleshooting)
// ==========================================

app.get('/api/debug/tickets', authenticateToken, (req, res) => {
    try {
        const tickets = db.prepare(`
            SELECT id, title, status, user_id, created_at, updated_at, resolved_at
            FROM tickets 
            ORDER BY id DESC
        `).all();
        
        console.log('Debug - Tickets in database:', tickets);
        
        res.json({
            total: tickets.length,
            tickets: tickets,
            message: 'Debug information'
        });
    } catch (error) {
        console.error('Debug error:', error);
        res.status(500).json({ error: error.message });
    }
});

app.get('/api/debug/ticket/:id', authenticateToken, (req, res) => {
    try {
        const ticketId = parseInt(req.params.id);
        const ticket = db.prepare('SELECT * FROM tickets WHERE id = ?').get(ticketId);
        
        if (!ticket) {
            // Check what IDs exist
            const allTicketIds = db.prepare('SELECT id FROM tickets ORDER BY id').all();
            return res.json({
                exists: false,
                requestedId: ticketId,
                availableIds: allTicketIds.map(t => t.id),
                message: `Ticket ID ${ticketId} not found`
            });
        }
        
        res.json({
            exists: true,
            ticket: ticket,
            message: `Ticket ID ${ticketId} exists`
        });
    } catch (error) {
        console.error('Debug ticket error:', error);
        res.status(500).json({ error: error.message });
    }
});

// Database schema info
app.get('/api/debug/schema', authenticateToken, (req, res) => {
    try {
        const ticketsInfo = db.prepare("PRAGMA table_info(tickets)").all();
        const usersInfo = db.prepare("PRAGMA table_info(users)").all();
        const commentsInfo = db.prepare("PRAGMA table_info(ticket_comments)").all();
        
        res.json({
            tickets: ticketsInfo,
            users: usersInfo,
            comments: commentsInfo
        });
    } catch (error) {
        console.error('Schema debug error:', error);
        res.status(500).json({ error: error.message });
    }
});

// ==========================================
// SERVER INITIALIZATION & LIFECYCLE
// ==========================================

function logStartup() {
    console.log("==================================================");
    console.log("ALTITUDE BPO ENTERPRISE SERVER STATUS");
    console.log(`Port: ${PORT}`);
    console.log(`Environment: ${process.env.NODE_ENV || 'Development'}`);
    console.log(`Database: ${path.join(__dirname, 'altitude.db')}`);
    console.log("==================================================");
    console.log("AVAILABLE ENDPOINTS:");
    console.log("  GET  /api/health");
    console.log("  POST /api/auth/login");
    console.log("  GET  /api/tickets");
    console.log("  GET  /api/tickets/:id");
    console.log("  POST /api/tickets");
    console.log("  PUT  /api/tickets/:id (for status updates)");
    console.log("  PUT  /api/tickets/:id/resolve (alternative)");
    console.log("  GET  /api/tickets/:id/comments");
    console.log("  POST /api/tickets/:id/comments");
    console.log("  GET  /api/dashboard/stats");
    console.log("  GET  /api/admin/users (admin only)");
    console.log("  POST /api/identity/provision (admin only)");
    console.log("  GET  /api/debug/* (debug endpoints)");
    console.log("==================================================");
}

// Initialize and start server
initDatabase();
logStartup();

app.listen(PORT, () => {
    console.log(`🚀 Altitude BPO Ticketing System running on port ${PORT}`);
    console.log(`📊 Database initialized: altitude.db`);
    console.log(`🔐 Default Admin: admin@altitudebpo.com / Altitude2026!`);
    console.log(`👤 Default User: user@altitudebpo.com / password123`);
    console.log(`👨‍💻 IT Staff: tech@altitudebpo.com / Tech2026!`);
    console.log(`🌐 API Base URL: http://localhost:${PORT}/api`);
    console.log(`🚀 Server ready at http://localhost:${PORT}`);
    console.log(`🔍 Debug endpoints available at /api/debug/*`);
});