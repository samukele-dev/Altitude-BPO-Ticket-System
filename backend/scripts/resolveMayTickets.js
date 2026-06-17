const { Pool } = require('pg');
require('dotenv').config();

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false }
});

async function resolveSpecificTickets() {
  const client = await pool.connect();
  
  try {
    console.log('🔍 Resolving specific tickets...');
    
    await client.query('BEGIN');
    
    // Update by ticket ID range (INC-595 to INC-600)
    const updateQuery = `
      UPDATE tickets 
      SET 
        status = 'resolved',
        resolved_at = CURRENT_TIMESTAMP,
        updated_at = CURRENT_TIMESTAMP
      WHERE id BETWEEN 368 AND 500
      RETURNING id, title, status
    `;
    
    const result = await client.query(updateQuery);
    
    await client.query('COMMIT');
    
    console.log(`✅ Updated ${result.rows.length} tickets to "resolved":`);
    result.rows.forEach(t => {
      console.log(`   Ticket #INC-${t.id}: ${t.title} -> ${t.status}`);
    });
    
  } catch (error) {
    await client.query('ROLLBACK');
    console.error('❌ Error:', error.message);
  } finally {
    client.release();
    await pool.end();
  }
}

resolveSpecificTickets().catch(console.error);