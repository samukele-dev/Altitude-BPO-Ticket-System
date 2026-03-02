/**
 * ALTITUDE BPO - ENHANCED TICKETING SYSTEM & IDENTITY MANAGER
 * Version: 2.0.1 (Enterprise Edition) - PostgreSQL Version
 */

require('dotenv').config();

const express = require('express');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { Pool } = require('pg');
const path = require('path');
const moment = require('moment');
const nodemailer = require('nodemailer');
const crypto = require('crypto');

const app = express();
const PORT = process.env.PORT || 5000; 
const SECRET_KEY = process.env.JWT_SECRET || "ALTITUDE_BPO_2026_SECURE_KEY";

const API_BASE = process.env.API_BASE || `http://localhost:${PORT}`;

// Update CORS configuration
app.use(cors({
  origin: process.env.FRONTEND_URL || 'http://localhost:3000',
  credentials: true
}));

// ==========================================
// POSTGRESQL CONNECTION
// ==========================================
let pool;

if (process.env.DATABASE_URL) {
  // Production (Render)
  pool = new Pool({
    connectionString: process.env.DATABASE_URL,
    ssl: {
      rejectUnauthorized: false
    }
  });
} else {
  // Development (Local PostgreSQL)
  pool = new Pool({
    user: process.env.DB_USER || 'postgres',
    host: process.env.DB_HOST || 'localhost',
    database: process.env.DB_NAME || 'altitude_bpo',
    password: process.env.DB_PASSWORD || 'postgres',
    port: process.env.DB_PORT || 5432,
  });
}

// Test database connection
pool.connect((err, client, release) => {
  if (err) {
    console.error('❌ Error connecting to PostgreSQL:', err.stack);
  } else {
    console.log('✅ Connected to PostgreSQL successfully');
    release();
  }
});

// ==========================================
// ON-PREMISES EXCHANGE EMAIL CONFIGURATION
// ==========================================
console.log('📧 On-Premises Exchange Configuration:');

let transporter;
let emailConfigured = false;

if (process.env.EMAIL_USER && process.env.EMAIL_PASS && 
    (process.env.EMAIL_USER.includes('@altitudebpo.co.za') || process.env.EMAIL_USER.includes('@altitudebpo.com'))) {
  
  console.log('✅ Exchange server credentials found');
  console.log('   Host:', process.env.EMAIL_HOST);
  console.log('   User:', process.env.EMAIL_USER);
  
  const emailConfig = {
    host: process.env.EMAIL_HOST || 'smtp.altitudebpo.co.za',
    port: parseInt(process.env.EMAIL_PORT) || 465,
    secure: process.env.EMAIL_SECURE === 'true',
    auth: {
      user: process.env.EMAIL_USER,
      pass: process.env.EMAIL_PASS
    },
    tls: {
      rejectUnauthorized: false,
      ciphers: 'SSLv3'
    }
  };
  
  transporter = nodemailer.createTransport(emailConfig);
  
  transporter.verify(function(error, success) {
    if (error) {
      console.error('❌ Exchange connection failed:', error.message);
      console.log('📝 Running in simulation mode for now');
      emailConfigured = false;
    } else {
      console.log('✅ Connected to Altitude BPO Exchange server successfully');
      emailConfigured = true;
    }
  });
  
} else {
  console.log('⚠️  Email credentials not configured');
  console.log('📝 Running in simulation mode');
  emailConfigured = false;
}

// ==========================================
// MIDDLEWARE CONFIGURATION
// ==========================================
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// ==========================================
// DATABASE INITIALIZATION
// ==========================================
async function initDatabase() {
    console.log('--- Initializing Database Schema ---');

    try {
        // Users table
        await pool.query(`
            CREATE TABLE IF NOT EXISTS users (
                id SERIAL PRIMARY KEY,
                uuid TEXT UNIQUE NOT NULL,
                name TEXT NOT NULL,
                email TEXT UNIQUE NOT NULL,
                password TEXT NOT NULL,
                role TEXT DEFAULT 'user',
                department TEXT,
                phone TEXT,
                avatar_color TEXT DEFAULT '#007bff',
                is_active INTEGER DEFAULT 1,
                last_login TIMESTAMP,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        `);
        console.log('✅ Users table ready');

        // Tickets table
        await pool.query(`
            CREATE TABLE IF NOT EXISTS tickets (
                id SERIAL PRIMARY KEY,
                uuid TEXT UNIQUE NOT NULL,
                title TEXT NOT NULL,
                description TEXT NOT NULL,
                status TEXT DEFAULT 'Open',
                priority TEXT DEFAULT 'Medium',
                category TEXT,
                user_id INTEGER REFERENCES users(id),
                assigned_to INTEGER REFERENCES users(id),
                resolved_at TIMESTAMP,
                due_date TIMESTAMP,
                estimated_time INTEGER,
                tags TEXT,
                attachments TEXT,
                device_name TEXT,
                device_brand TEXT,
                device_period TEXT,
                campaign TEXT,
                number_of_agents INTEGER DEFAULT 1,
                start_date TEXT,
                training_period TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        `);
        console.log('✅ Tickets table ready');

        // Comments table
        await pool.query(`
            CREATE TABLE IF NOT EXISTS ticket_comments (
                id SERIAL PRIMARY KEY,
                uuid TEXT UNIQUE NOT NULL,
                ticket_id INTEGER REFERENCES tickets(id) ON DELETE CASCADE,
                user_id INTEGER REFERENCES users(id),
                message TEXT NOT NULL,
                is_internal INTEGER DEFAULT 0,
                attachments TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        `);
        console.log('✅ Comments table ready');

        // Activity log table
        await pool.query(`
            CREATE TABLE IF NOT EXISTS activity_log (
                id SERIAL PRIMARY KEY,
                user_id INTEGER REFERENCES users(id),
                action TEXT NOT NULL,
                entity_type TEXT,
                entity_id INTEGER,
                details TEXT,
                ip_address TEXT,
                user_agent TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        `);
        console.log('✅ Activity log table ready');

        // Identity provisions table
        await pool.query(`
            CREATE TABLE IF NOT EXISTS identity_provisions (
                id SERIAL PRIMARY KEY,
                request_uuid TEXT UNIQUE NOT NULL,
                full_name TEXT NOT NULL,
                corporate_email TEXT NOT NULL,
                department TEXT,
                role_profile TEXT,
                status TEXT DEFAULT 'Pending',
                authorized_by INTEGER REFERENCES users(id),
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        `);
        console.log('✅ Identity provisions table ready');

        // Create indexes
        await pool.query('CREATE INDEX IF NOT EXISTS idx_tickets_status ON tickets(status)');
        await pool.query('CREATE INDEX IF NOT EXISTS idx_tickets_user ON tickets(user_id)');
        await pool.query('CREATE INDEX IF NOT EXISTS idx_comments_ticket ON ticket_comments(ticket_id)');
        await pool.query('CREATE INDEX IF NOT EXISTS idx_identity_email ON identity_provisions(corporate_email)');
        
        console.log('✅ Indexes created');

        await seedInitialData();

    } catch (error) {
        console.error('❌ Database initialization error:', error);
        throw error;
    }
}

async function seedInitialData() {
    try {
        // Admin setup
        const adminExists = await pool.query('SELECT id FROM users WHERE email = $1', ['admin@altitudebpo.com']);
        if (adminExists.rows.length === 0) {
            const hashedPassword = await bcrypt.hash('Altitude2026!', 10);
            await pool.query(
                'INSERT INTO users (uuid, name, email, password, role, department, phone, avatar_color) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)',
                [generateUUID(), 'System Administrator', 'admin@altitudebpo.com', hashedPassword, 'it_admin', 'IT Department', '+27 11 123 4567', '#dc3545']
            );
            console.log('✅ Admin user created');
        }

        // Demo user setup
        const userExists = await pool.query('SELECT id FROM users WHERE email = $1', ['user@altitudebpo.com']);
        if (userExists.rows.length === 0) {
            const hashedPassword = await bcrypt.hash('password123', 10);
            await pool.query(
                'INSERT INTO users (uuid, name, email, password, role, department, phone, avatar_color) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)',
                [generateUUID(), 'Demo User', 'user@altitudebpo.com', hashedPassword, 'user', 'Sales Department', '+27 11 987 6543', '#28a745']
            );
            console.log('✅ Demo user created');
        }

        // IT Staff setup
        const techExists = await pool.query('SELECT id FROM users WHERE email = $1', ['tech@altitudebpo.com']);
        if (techExists.rows.length === 0) {
            const hashedPassword = await bcrypt.hash('Tech2026!', 10);
            await pool.query(
                'INSERT INTO users (uuid, name, email, password, role, department, phone, avatar_color) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)',
                [generateUUID(), 'IT Support Staff', 'tech@altitudebpo.com', hashedPassword, 'it_admin', 'IT Department', '+27 11 555 1234', '#3B82F6']
            );
            console.log('✅ IT Staff user created');
        }
    } catch (error) {
        console.error('❌ Error seeding data:', error);
    }
}

// ==========================================
// UTILITY FUNCTIONS
// ==========================================
function generateUUID() {
    return crypto.randomUUID();
}

async function logActivity(userId, action, entityType = null, entityId = null, details = null, req = null) {
    try {
        await pool.query(
            'INSERT INTO activity_log (user_id, action, entity_type, entity_id, details, ip_address, user_agent) VALUES ($1, $2, $3, $4, $5, $6, $7)',
            [userId, action, entityType, entityId, details, req?.ip || '127.0.0.1', req?.headers['user-agent']]
        );
    } catch (error) {
        console.error('Activity log error:', error);
    }
}

// Function to update stale tickets (call this periodically)
async function updateStaleTickets() {
    try {
        const staleDate = new Date();
        staleDate.setDate(staleDate.getDate() - 7); // 7 days old
        
        const result = await pool.query(`
            UPDATE tickets 
            SET status = 'Closed',
                updated_at = CURRENT_TIMESTAMP
            WHERE status = 'Open' 
            AND created_at < $1
            AND due_date < CURRENT_TIMESTAMP
        `, [staleDate.toISOString()]);

        if (result.rowCount > 0) {
            console.log(`Auto-closed ${result.rowCount} stale tickets`);
            logActivity(1, 'SYSTEM_AUTO_CLOSE', 'ticket', null, `Auto-closed ${result.rowCount} stale tickets`);
        }
    } catch (error) {
        console.error('Auto-close error:', error);
    }
}

// Call this function periodically (e.g., once a day)
setInterval(updateStaleTickets, 24 * 60 * 60 * 1000); // Every 24 hours

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
// API ROUTES: DASHBOARD & ANALYTICS
// ==========================================

app.get('/api/dashboard/stats', authenticateToken, async (req, res) => {
    try {
        console.log(`GET /api/dashboard/stats called by user ${req.user.id} (role: ${req.user.role})`);
        
        let query = 'SELECT COUNT(*) as count FROM tickets';
        let params = [];
        
        if (req.user.role !== 'it_admin') {
            query += ' WHERE user_id = $1';
            params.push(req.user.id);
        }
        
        const totalResult = await pool.query(query, params);
        const totalCount = parseInt(totalResult.rows[0].count);
        
        console.log(`Total tickets found: ${totalCount}`);
        
        const stats = {
            total: totalCount,
            open: 0,
            in_progress: 0,
            resolved: 0,
            closed: 0,
            critical: 0,
            high: 0,
            medium: 0,
            low: 0
        };
        
        if (totalCount > 0) {
            let statsQuery = `
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
            `;
            
            if (req.user.role !== 'it_admin') {
                statsQuery += ' WHERE user_id = $1';
                const statsResult = await pool.query(statsQuery, [req.user.id]);
                const row = statsResult.rows[0];
                
                stats.open = parseInt(row.open) || 0;
                stats.in_progress = parseInt(row.in_progress) || 0;
                stats.resolved = parseInt(row.resolved) || 0;
                stats.closed = parseInt(row.closed) || 0;
                stats.critical = parseInt(row.critical) || 0;
                stats.high = parseInt(row.high) || 0;
                stats.medium = parseInt(row.medium) || 0;
                stats.low = parseInt(row.low) || 0;
            } else {
                const statsResult = await pool.query(statsQuery);
                const row = statsResult.rows[0];
                
                stats.open = parseInt(row.open) || 0;
                stats.in_progress = parseInt(row.in_progress) || 0;
                stats.resolved = parseInt(row.resolved) || 0;
                stats.closed = parseInt(row.closed) || 0;
                stats.critical = parseInt(row.critical) || 0;
                stats.high = parseInt(row.high) || 0;
                stats.medium = parseInt(row.medium) || 0;
                stats.low = parseInt(row.low) || 0;
            }
        }
        
        console.log('Stats calculated:', stats);

        // Get recent tickets
        let recentQuery = `
            SELECT t.*, u.name as requester_name, u.avatar_color as requester_avatar
            FROM tickets t
            LEFT JOIN users u ON t.user_id = u.id
        `;
        
        let recentResult;
        if (req.user.role !== 'it_admin') {
            recentQuery += ' WHERE t.user_id = $1 ORDER BY t.created_at DESC LIMIT 10';
            recentResult = await pool.query(recentQuery, [req.user.id]);
        } else {
            recentQuery += ' ORDER BY t.created_at DESC LIMIT 10';
            recentResult = await pool.query(recentQuery);
        }
        
        const recentTickets = recentResult.rows;

        res.json({ 
            stats, 
            recentTickets
        });
        
    } catch (error) {
        console.error('Dashboard stats error:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

// ==========================================
// LOGIN
// ==========================================
app.post('/api/auth/login', async (req, res) => {
    try {
        const { email, password } = req.body;
        if (!email || !password) return res.status(400).json({ error: 'Email and password are required' });

        const result = await pool.query('SELECT * FROM users WHERE email = $1 AND is_active = 1', [email]);
        const user = result.rows[0];
        
        if (!user || !(await bcrypt.compare(password, user.password))) {
            return res.status(401).json({ error: 'Invalid credentials' });
        }

        await pool.query('UPDATE users SET last_login = CURRENT_TIMESTAMP WHERE id = $1', [user.id]);

        const token = jwt.sign(
            { id: user.id, uuid: user.uuid, name: user.name, email: user.email, role: user.role, department: user.department, avatar_color: user.avatar_color },
            SECRET_KEY, { expiresIn: '24h' }
        );

        const { password: _, ...userWithoutPassword } = user;
        await logActivity(user.id, 'USER_LOGIN', 'user', user.id, 'User logged in', req);
        res.json({ token, user: userWithoutPassword });
    } catch (error) {
        console.error('Login error:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

// ==========================================
// API ROUTES: IDENTITY MANAGEMENT
// ==========================================

app.post('/api/identity/provision', authenticateToken, async (req, res) => {
    try {
        const { full_name, corporate_email, department, role_profile, temporary_access_key } = req.body;

        if (!full_name || !corporate_email) {
            return res.status(400).json({ error: 'Critical: Full name and Email are required for provisioning.' });
        }

        if (!corporate_email.endsWith('@altitudebpo.co.za') && !corporate_email.endsWith('@altitudebpo.com')) {
            return res.status(400).json({ error: 'Critical: Identity must use a valid corporate domain.' });
        }

        const existing = await pool.query('SELECT id FROM users WHERE email = $1', [corporate_email]);
        if (existing.rows.length > 0) {
            return res.status(400).json({ error: 'Critical: Identity already exists in the system.' });
        }

        const hashedPassword = await bcrypt.hash(temporary_access_key || 'Default2026!', 10);
        const userUuid = generateUUID();

        const result = await pool.query(
            'INSERT INTO users (uuid, name, email, password, role, department, avatar_color) VALUES ($1, $2, $3, $4, $5, $6, $7) RETURNING id',
            [userUuid, full_name, corporate_email, hashedPassword, role_profile === 'Standard User' ? 'user' : 'it_admin', department, '#5f6368']
        );

        await pool.query(
            'INSERT INTO identity_provisions (request_uuid, full_name, corporate_email, department, role_profile, status, authorized_by) VALUES ($1, $2, $3, $4, $5, $6, $7)',
            [generateUUID(), full_name, corporate_email, department, role_profile, 'Completed', req.user.id]
        );

        await logActivity(req.user.id, 'IDENTITY_PROVISIONED', 'user', result.rows[0].id, `Provisioned: ${corporate_email}`, req);

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

app.get('/api/admin/users', authenticateToken, isAdmin, async (req, res) => {
    try {
        console.log('Fetching all users for Identity Manager...');
        
        const result = await pool.query(`
            SELECT 
                id, uuid, name, email, role, department, 
                avatar_color, is_active, last_login, created_at
            FROM users 
            ORDER BY created_at DESC
        `);
        
        console.log(`Found ${result.rows.length} users`);
        res.json(result.rows);
    } catch (error) {
        console.error('Error fetching users:', error);
        res.status(500).json({ error: 'Internal server error while fetching users' });
    }
});

// ==========================================
// API ROUTES: USER MANAGEMENT
// ==========================================

app.put('/api/admin/users/:id/password', authenticateToken, isAdmin, async (req, res) => {
  try {
    const userId = parseInt(req.params.id);
    const { new_password } = req.body;

    if (!new_password || new_password.length < 6) {
      return res.status(400).json({ error: 'Password must be at least 6 characters long' });
    }

    const user = await pool.query('SELECT id FROM users WHERE id = $1', [userId]);
    if (user.rows.length === 0) {
      return res.status(404).json({ error: 'User not found' });
    }

    const hashedPassword = await bcrypt.hash(new_password, 10);

    await pool.query('UPDATE users SET password = $1, updated_at = CURRENT_TIMESTAMP WHERE id = $2',
      [hashedPassword, userId]);

    await logActivity(req.user.id, 'USER_PASSWORD_RESET', 'user', userId, `Password reset for user ID ${userId}`, req);

    res.json({
      success: true,
      message: 'Password updated successfully',
      user_id: userId
    });
  } catch (error) {
    console.error('Password update error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

app.get('/api/admin/users/:id/activity', authenticateToken, isAdmin, async (req, res) => {
  try {
    const userId = parseInt(req.params.id);

    const user = await pool.query('SELECT id, name, email FROM users WHERE id = $1', [userId]);
    if (user.rows.length === 0) {
      return res.status(404).json({ error: 'User not found' });
    }

    const activities = await pool.query(`
      SELECT 
        al.*,
        u.name as performed_by_name,
        u.email as performed_by_email
      FROM activity_log al
      LEFT JOIN users u ON al.user_id = u.id
      WHERE al.user_id = $1 OR al.entity_id = $1
      ORDER BY al.created_at DESC
      LIMIT 50
    `, [userId, userId]);

    res.json({
      user: user.rows[0],
      activities: activities.rows,
      count: activities.rows.length
    });
  } catch (error) {
    console.error('Activity fetch error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

app.put('/api/admin/users/:id/toggle-status', authenticateToken, isAdmin, async (req, res) => {
  try {
    const userId = parseInt(req.params.id);
    
    const user = await pool.query('SELECT id, is_active, name FROM users WHERE id = $1', [userId]);
    if (user.rows.length === 0) {
      return res.status(404).json({ error: 'User not found' });
    }

    const currentStatus = user.rows[0].is_active;
    const newStatus = currentStatus === 1 ? 0 : 1;
    const statusText = newStatus === 1 ? 'activated' : 'deactivated';
    
    await pool.query('UPDATE users SET is_active = $1, updated_at = CURRENT_TIMESTAMP WHERE id = $2',
      [newStatus, userId]);

    await logActivity(req.user.id, 'USER_STATUS_CHANGED', 'user', userId, 
      `User ${statusText}: ${user.rows[0].name} (ID: ${userId})`, req);

    res.json({
      success: true,
      message: `User ${statusText} successfully`,
      user_id: userId,
      is_active: newStatus
    });
  } catch (error) {
    console.error('Toggle status error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

app.get('/api/admin/users/:id', authenticateToken, isAdmin, async (req, res) => {
  try {
    const userId = parseInt(req.params.id);
    
    const user = await pool.query(`
      SELECT 
        id, uuid, name, email, role, department, 
        avatar_color, is_active, last_login, created_at, phone
      FROM users 
      WHERE id = $1
    `, [userId]);

    if (user.rows.length === 0) {
      return res.status(404).json({ error: 'User not found' });
    }

    res.json({ user: user.rows[0] });
  } catch (error) {
    console.error('Get user error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

app.put('/api/admin/users/:id', authenticateToken, isAdmin, async (req, res) => {
  try {
    const userId = parseInt(req.params.id);
    const { name, department, role, phone } = req.body;

    const existingUser = await pool.query('SELECT id FROM users WHERE id = $1', [userId]);
    if (existingUser.rows.length === 0) {
      return res.status(404).json({ error: 'User not found' });
    }

    await pool.query(`
      UPDATE users 
      SET name = $1, department = $2, role = $3, phone = $4, updated_at = CURRENT_TIMESTAMP
      WHERE id = $5
    `, [name || '', department || '', role || 'user', phone || '', userId]);

    await logActivity(req.user.id, 'USER_UPDATED', 'user', userId, 'User details updated', req);

    res.json({
      success: true,
      message: 'User updated successfully',
      user_id: userId
    });
  } catch (error) {
    console.error('Update user error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// ==========================================
// API ROUTES: TICKETING SYSTEM
// ==========================================

app.get('/api/tickets', authenticateToken, async (req, res) => {
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
        let paramIndex = 1;

        if (req.user.role !== 'it_admin') {
            query += ' WHERE t.user_id = $' + paramIndex;
            params.push(req.user.id);
            paramIndex++;
        }

        if (req.query.status && req.query.status !== 'all') {
            if (params.length === 0) {
                query += ' WHERE t.status = $' + paramIndex;
            } else {
                query += ' AND t.status = $' + paramIndex;
            }
            params.push(req.query.status);
            paramIndex++;
        }

        query += ' ORDER BY t.created_at DESC';
        
        const result = await pool.query(query, params);
        res.json(result.rows);
    } catch (error) {
        console.error('Error fetching tickets:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

app.get('/api/tickets/:id', authenticateToken, async (req, res) => {
    try {
        console.log(`GET /api/tickets/${req.params.id} called by user ${req.user.id}`);
        
        const ticketId = parseInt(req.params.id);
        if (isNaN(ticketId)) {
            return res.status(400).json({ error: 'Invalid ticket ID' });
        }

        const result = await pool.query(`
            SELECT t.*, 
                   u.name as requester_name, u.email as requester_email, u.department as requester_dept,
                   u.avatar_color as requester_avatar,
                   a.name as assigned_name, a.email as assigned_email
            FROM tickets t
            LEFT JOIN users u ON t.user_id = u.id
            LEFT JOIN users a ON t.assigned_to = a.id
            WHERE t.id = $1
        `, [ticketId]);

        const ticket = result.rows[0];
        
        if (!ticket) {
            console.log(`Ticket ID ${ticketId} not found in database`);
            return res.status(404).json({ 
                error: 'Ticket not found',
                details: `Ticket with ID ${ticketId} does not exist in the database`
            });
        }

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

app.post('/api/tickets', authenticateToken, async (req, res) => {
  try {
    const { 
      title, description, priority, category, 
      device_name, device_brand, device_period, 
      number_of_agents, training_period, start_date, campaign 
    } = req.body;
    
    if (!title || !description) return res.status(400).json({ error: 'Title and description are required' });

    const dueDate = new Date();
    dueDate.setDate(dueDate.getDate() + (priority === 'Critical' ? 1 : 7));

    const result = await pool.query(`
      INSERT INTO tickets (
        uuid, title, description, priority, category, 
        user_id, due_date, tags, 
        device_name, device_brand, device_period, 
        number_of_agents, training_period, campaign, start_date,
        created_at, updated_at
      )
      VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
      RETURNING id
    `, [
      generateUUID(),
      title,
      description,
      priority || 'Medium',
      category || 'General',
      req.user.id,
      dueDate.toISOString(),
      category === 'Resignation' ? 'Resignation-Device-Return' : '',
      device_name || null,
      device_brand || null,
      device_period || null,
      number_of_agents || null,
      training_period || null,
      campaign || null,
      start_date || null
    ]);

    const newTicketId = result.rows[0].id;

    await logActivity(req.user.id, 'TICKET_CREATED', 'ticket', newTicketId, `Created ticket: ${title}`, req);

    const newTicketResult = await pool.query(`
      SELECT t.*, u.name as requester_name, u.email as requester_email, u.avatar_color as requester_avatar
      FROM tickets t
      JOIN users u ON t.user_id = u.id
      WHERE t.id = $1
    `, [newTicketId]);

    const newTicket = newTicketResult.rows[0];

    console.log('✅ Ticket created successfully:', {
      id: newTicket.id,
      campaign: newTicket.campaign,
      number_of_agents: newTicket.number_of_agents,
      start_date: newTicket.start_date,
      training_period: newTicket.training_period
    });

    res.status(201).json({ 
      success: true, 
      ticket: newTicket,
      message: 'Ticket created successfully'
    });
  } catch (error) {
    console.error('❌ Ticket creation error:', error);
    res.status(500).json({ error: 'Internal server error: ' + error.message });
  }
});

app.get('/api/tickets/:id/comments', authenticateToken, async (req, res) => {
    try {
        console.log(`GET /api/tickets/${req.params.id}/comments called`);
        
        const ticketId = parseInt(req.params.id);
        if (isNaN(ticketId)) {
            return res.status(400).json({ error: 'Invalid ticket ID' });
        }

        const ticketExists = await pool.query('SELECT id FROM tickets WHERE id = $1', [ticketId]);
        if (ticketExists.rows.length === 0) {
            return res.status(404).json({ error: 'Ticket not found' });
        }

        const comments = await pool.query(`
            SELECT tc.*, u.name as user_name, u.role as user_role, u.avatar_color as user_avatar
            FROM ticket_comments tc
            JOIN users u ON tc.user_id = u.id
            WHERE tc.ticket_id = $1 
            ORDER BY tc.created_at ASC
        `, [ticketId]);
        
        res.json(comments.rows);
    } catch (error) {
        console.error('Comments fetch error:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

app.post('/api/tickets/:id/comments', authenticateToken, async (req, res) => {
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

        const ticketExists = await pool.query('SELECT id, user_id FROM tickets WHERE id = $1', [ticketId]);
        if (ticketExists.rows.length === 0) {
            return res.status(404).json({ error: 'Ticket not found' });
        }

        if (req.user.role !== 'it_admin' && ticketExists.rows[0].user_id !== req.user.id) {
            return res.status(403).json({ error: 'Access denied' });
        }

        const result = await pool.query(`
            INSERT INTO ticket_comments (uuid, ticket_id, user_id, message, created_at, updated_at)
            VALUES ($1, $2, $3, $4, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
            RETURNING id
        `, [generateUUID(), ticketId, req.user.id, commentText.trim()]);
        
        const newCommentResult = await pool.query(`
            SELECT tc.*, u.name as user_name, u.role as user_role, u.avatar_color as user_avatar
            FROM ticket_comments tc
            JOIN users u ON tc.user_id = u.id
            WHERE tc.id = $1
        `, [result.rows[0].id]);
        
        await logActivity(req.user.id, 'COMMENT_ADDED', 'ticket_comment', ticketId, `Added comment to ticket ${ticketId}`, req);
        
        res.status(201).json({ 
            success: true, 
            comment: newCommentResult.rows[0],
            message: 'Comment added successfully'
        });
    } catch (error) {
        console.error('Comment creation error:', error);
        res.status(500).json({ error: 'Internal server error: ' + error.message });
    }
});

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

    const ticketResult = await pool.query(`
      SELECT t.*, u.name as requester_name, u.email as requester_email
      FROM tickets t
      LEFT JOIN users u ON t.user_id = u.id
      WHERE t.id = $1
    `, [ticketId]);

    const ticket = ticketResult.rows[0];

    if (!ticket) {
      return res.status(404).json({ error: 'Ticket not found' });
    }

    if (req.user.role !== 'it_admin' && ticket.user_id !== req.user.id) {
      return res.status(403).json({ error: 'Access denied' });
    }

    const hasEmailConfig = process.env.EMAIL_USER && 
                          process.env.EMAIL_PASS &&
                          process.env.EMAIL_USER !== 'your-email@gmail.com';

    if (!hasEmailConfig) {
      console.log(`📝 Email simulation mode - No email credentials configured`);
      
      await logActivity(req.user.id, 'TICKET_FORWARDED', 'ticket', ticketId, 
        `Simulated forwarding to ${email}`, req);
      
      const forwardComment = `Ticket forwarded to ${email} by ${req.user.name}. ${message ? `Note: ${message}` : ''} [EMAIL SIMULATION MODE]`;
      
      await pool.query(`
        INSERT INTO ticket_comments (uuid, ticket_id, user_id, message, is_internal, created_at, updated_at)
        VALUES ($1, $2, $3, $4, $5, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
      `, [generateUUID(), ticketId, req.user.id, forwardComment, 1]);
      
      return res.json({
        success: true,
        message: `Ticket forwarding logged for ${email}. Configure email in .env file to send actual emails.`,
        emailSent: false,
        simulation: true
      });
    }

    // ... email sending code would go here ...

  } catch (error) {
    console.error('Ticket forwarding error:', error);
    return res.status(500).json({ 
      error: 'Internal server error',
      details: error.message 
    });
  }
});

app.put('/api/tickets/:id', authenticateToken, async (req, res) => {
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
        
        const validStatuses = ['Open', 'In Progress', 'Resolved', 'Closed'];
        if (status && !validStatuses.includes(status)) {
            console.log('Invalid status:', status);
            return res.status(400).json({ 
                error: 'Invalid status', 
                validStatuses: validStatuses 
            });
        }

        const ticketResult = await pool.query('SELECT * FROM tickets WHERE id = $1', [ticketId]);
        const ticket = ticketResult.rows[0];
        
        if (!ticket) {
            console.log(`Ticket ID ${ticketId} not found in database`);
            return res.status(404).json({ 
                error: 'Ticket not found',
                message: `Ticket with ID ${ticketId} does not exist in the database`
            });
        }

        if (req.user.role !== 'it_admin' && ticket.user_id !== req.user.id) {
            console.log(`Permission denied: User ${req.user.id} cannot modify ticket ${ticketId} (owner: ${ticket.user_id})`);
            return res.status(403).json({ 
                error: 'Access denied',
                message: 'Only ticket owner or administrator can modify tickets'
            });
        }

        let updateQuery = 'UPDATE tickets SET updated_at = CURRENT_TIMESTAMP';
        const params = [];
        let paramIndex = 1;
        
        if (status) {
            updateQuery += ', status = $' + paramIndex;
            params.push(status);
            paramIndex++;
            
            if (status === 'Resolved' || status === 'Closed') {
                updateQuery += ', resolved_at = CURRENT_TIMESTAMP';
            }
        }
        
        updateQuery += ' WHERE id = $' + paramIndex;
        params.push(ticketId);
        
        await pool.query(updateQuery, params);
        
        const action = status === 'Resolved' ? 'TICKET_RESOLVED' : 
                      status === 'Closed' ? 'TICKET_CLOSED' : 'TICKET_UPDATED';
        
        await logActivity(req.user.id, action, 'ticket', ticketId, `Status changed to ${status}`, req);
        
        if (resolution_note && resolution_note.trim() !== '') {
            const commentMessage = status === 'Resolved' || status === 'Closed' 
                ? `Ticket ${status.toLowerCase()}: ${resolution_note}`
                : `Status updated to ${status}: ${resolution_note}`;
            
            await pool.query(`
                INSERT INTO ticket_comments (uuid, ticket_id, user_id, message, is_internal, created_at, updated_at)
                VALUES ($1, $2, $3, $4, $5, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
            `, [generateUUID(), ticketId, req.user.id, commentMessage.trim(), 1]);
        }
        
        const updatedTicketResult = await pool.query(`
            SELECT t.*, 
                   u.name as requester_name, u.email as requester_email, 
                   u.department as requester_dept, u.avatar_color as requester_avatar,
                   a.name as assigned_name, a.email as assigned_email
            FROM tickets t
            LEFT JOIN users u ON t.user_id = u.id
            LEFT JOIN users a ON t.assigned_to = a.id
            WHERE t.id = $1
        `, [ticketId]);
        
        res.json({ 
            success: true, 
            message: `Ticket ${status ? status.toLowerCase() : 'updated'} successfully`,
            status: status,
            ticket: updatedTicketResult.rows[0]
        });
        
    } catch (error) {
        console.error('Ticket update error:', error);
        res.status(500).json({ 
            error: 'Internal server error',
            message: error.message
        });
    }
});

// ==========================================
// SERVER INITIALIZATION & LIFECYCLE
// ==========================================

async function startServer() {
    try {
        await initDatabase();
        
        console.log("==================================================");
        console.log("ALTITUDE BPO ENTERPRISE SERVER STATUS");
        console.log(`Port: ${PORT}`);
        console.log(`Environment: ${process.env.NODE_ENV || 'Development'}`);
        console.log(`Database: PostgreSQL`);
        console.log("==================================================");
        console.log("AVAILABLE ENDPOINTS:");
        console.log("  GET  /api/health");
        console.log("  POST /api/auth/login");
        console.log("  GET  /api/tickets");
        console.log("  GET  /api/tickets/:id");
        console.log("  POST /api/tickets");
        console.log("  PUT  /api/tickets/:id (for status updates)");
        console.log("  GET  /api/tickets/:id/comments");
        console.log("  POST /api/tickets/:id/comments");
        console.log("  GET  /api/dashboard/stats");
        console.log("  GET  /api/admin/users (admin only)");
        console.log("  POST /api/identity/provision (admin only)");
        console.log("==================================================");
        
        app.listen(PORT, () => {
            console.log(`🚀 Altitude BPO Ticketing System running on port ${PORT}`);
            console.log(`🔐 Default Admin: admin@altitudebpo.com / Altitude2026!`);
            console.log(`👤 Default User: user@altitudebpo.com / password123`);
            console.log(`👨‍💻 IT Staff: tech@altitudebpo.com / Tech2026!`);
            console.log(`🌐 API Base URL: http://localhost:${PORT}/api`);
        });
    } catch (error) {
        console.error('❌ Failed to start server:', error);
        process.exit(1);
    }
}

startServer();