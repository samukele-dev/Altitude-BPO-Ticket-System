const { Pool } = require('pg');
require('dotenv').config();

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false }
});

async function resolveClosedTickets() {
  const client = await pool.connect();
  
  try {
    console.log('🔍 Resolving CLOSED tickets from May 2026...');
    
    await client.query('BEGIN');
    
    // Update ONLY closed tickets between IDs 368-500
    const updateQuery = `
      UPDATE tickets 
      SET 
        status = 'resolved',
        resolved_at = CURRENT_TIMESTAMP,
        updated_at = CURRENT_TIMESTAMP
      WHERE id BETWEEN 368 AND 500
      AND status = 'closed'
      RETURNING id, title, status
    `;
    
    const result = await client.query(updateQuery);
    
    await client.query('COMMIT');
    
    console.log(`✅ Updated ${result.rows.length} tickets from "closed" to "resolved":`);
    result.rows.forEach(t => {
      console.log(`   Ticket #INC-${t.id}: ${t.title} -> ${t.status}`);
    });
    
    // Show what's still open
    const openTickets = await client.query(`
      SELECT id, title, status 
      FROM tickets 
      WHERE id BETWEEN 368 AND 500
      AND status = 'open'
      ORDER BY id
    `);
    
    if (openTickets.rows.length > 0) {
      console.log(`\n⚠️ These tickets are still "Open" (not updated):`);
      openTickets.rows.forEach(t => {
        console.log(`   Ticket #INC-${t.id}: ${t.title} -> ${t.status}`);
      });
    }
    
  } catch (error) {
    await client.query('ROLLBACK');
    console.error('❌ Error:', error.message);
  } finally {
    client.release();
    await pool.end();
  }
}

resolveClosedTickets().catch(console.error);