const { Pool } = require('pg');
require('dotenv').config();

// Database connection with SSL for Render
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: {
    rejectUnauthorized: false
  }
});

async function resolveMayTickets() {
  const client = await pool.connect();
  
  try {
    console.log('🔍 Starting to RESOLVE tickets from May 2026...');
    
    await client.query('BEGIN');
    
    // FIRST - Check what tickets exist and their statuses
    console.log('\n📊 Checking all tickets from May 2026:');
    const allMayTickets = await client.query(`
      SELECT id, title, status, created_at 
      FROM tickets 
      WHERE created_at >= '2026-05-01' 
      AND created_at < '2026-06-01'
      ORDER BY created_at DESC
    `);
    
    console.log(`Found ${allMayTickets.rows.length} tickets in May 2026:`);
    allMayTickets.rows.forEach(t => {
      console.log(`   ID: ${t.id}, Title: "${t.title}", Status: "${t.status}", Created: ${t.created_at}`);
    });
    
    if (allMayTickets.rows.length === 0) {
      console.log('⚠️  No tickets found for May 2026!');
      console.log('💡 Try adjusting the date filter or check your database.');
      await client.query('ROLLBACK');
      return;
    }
    
    // Now update ALL May tickets to "resolved" (including "closed")
    console.log('\n🔄 Updating ALL May tickets to "resolved"...');
    
    const updateQuery = `
      UPDATE tickets 
      SET 
        status = 'resolved',
        resolved_at = CURRENT_TIMESTAMP,
        updated_at = CURRENT_TIMESTAMP
      WHERE created_at >= '2026-05-01' 
      AND created_at < '2026-06-01'
      RETURNING id, title, status
    `;
    
    const updateResult = await client.query(updateQuery);
    
    await client.query('COMMIT');
    
    console.log(`\n✅ Successfully updated ${updateResult.rows.length} tickets to "resolved"!`);
    
    // Show updated tickets
    console.log('\n📋 Updated tickets:');
    updateResult.rows.forEach(t => {
      console.log(`   ID: ${t.id}, Title: "${t.title}", New Status: "${t.status}"`);
    });
    
    // Verify final status
    const finalCheck = await client.query(`
      SELECT 
        COUNT(*) FILTER (WHERE status = 'open') as open,
        COUNT(*) FILTER (WHERE status = 'in_progress') as in_progress,
        COUNT(*) FILTER (WHERE status = 'pending') as pending,
        COUNT(*) FILTER (WHERE status = 'resolved') as resolved,
        COUNT(*) FILTER (WHERE status = 'closed') as closed
      FROM tickets 
      WHERE created_at >= '2026-05-01' 
      AND created_at < '2026-06-01'
    `);
    
    console.log(`\n📈 Final Status for May 2026:`);
    console.log(`   Open: ${finalCheck.rows[0].open}`);
    console.log(`   In Progress: ${finalCheck.rows[0].in_progress}`);
    console.log(`   Pending: ${finalCheck.rows[0].pending}`);
    console.log(`   Resolved: ${finalCheck.rows[0].resolved} ✅`);
    console.log(`   Closed: ${finalCheck.rows[0].closed}`);
    
  } catch (error) {
    await client.query('ROLLBACK');
    console.error('❌ Error:', error.message);
    throw error;
  } finally {
    client.release();
    await pool.end();
  }
}

resolveMayTickets().catch(console.error);