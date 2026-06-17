const { Pool } = require('pg');
require('dotenv').config();

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false }
});

async function resolveAprilTickets() {
  const client = await pool.connect();
  
  try {
    console.log('🔍 Resolving OPEN tickets from APRIL 2026...');
    
    await client.query('BEGIN');
    
    // First, check how many OPEN tickets exist in April
    const checkQuery = `
      SELECT 
        COUNT(*) as total_open,
        array_agg(id) as ticket_ids,
        array_agg(title) as ticket_titles
      FROM tickets 
      WHERE created_at >= '2026-04-01' 
      AND created_at < '2026-05-01'
      AND status = 'open'
    `;
    
    const checkResult = await client.query(checkQuery);
    const openCount = parseInt(checkResult.rows[0].total_open) || 0;
    
    console.log(`📊 Found ${openCount} OPEN tickets in April 2026`);
    
    if (openCount === 0) {
      console.log('ℹ️  No OPEN tickets found in April 2026.');
      await client.query('ROLLBACK');
      return;
    }
    
    // Show preview of tickets to be updated
    const previewQuery = `
      SELECT id, title, status, created_at
      FROM tickets 
      WHERE created_at >= '2026-04-01' 
      AND created_at < '2026-05-01'
      AND status = 'open'
      ORDER BY id
    `;
    
    const previewResult = await client.query(previewQuery);
    console.log('\n📋 Tickets to be updated (OPEN → RESOLVED):');
    previewResult.rows.forEach(t => {
      const date = new Date(t.created_at).toLocaleDateString();
      console.log(`   #INC-${t.id}: ${t.title} (${date}) - Current: ${t.status}`);
    });
    
    // Ask for confirmation
    console.log(`\n⚠️  This will update ${openCount} tickets from "OPEN" to "RESOLVED"`);
    console.log('Press Ctrl+C to cancel, or wait 5 seconds to continue...');
    await new Promise(resolve => setTimeout(resolve, 5000));
    
    // Update ALL OPEN tickets from April 2026 to RESOLVED
    const updateQuery = `
      UPDATE tickets 
      SET 
        status = 'resolved',
        resolved_at = CURRENT_TIMESTAMP,
        updated_at = CURRENT_TIMESTAMP
      WHERE created_at >= '2026-04-01' 
      AND created_at < '2026-05-01'
      AND status = 'open'
      RETURNING id, title, status
    `;
    
    const result = await client.query(updateQuery);
    
    await client.query('COMMIT');
    
    console.log(`\n✅ Successfully updated ${result.rows.length} tickets from OPEN to RESOLVED!`);
    result.rows.forEach(t => {
      console.log(`   Ticket #INC-${t.id}: ${t.title} -> ${t.status}`);
    });
    
    // Show summary
    const summaryQuery = `
      SELECT 
        COUNT(*) FILTER (WHERE status = 'open') as open,
        COUNT(*) FILTER (WHERE status = 'in_progress') as in_progress,
        COUNT(*) FILTER (WHERE status = 'pending') as pending,
        COUNT(*) FILTER (WHERE status = 'resolved') as resolved,
        COUNT(*) FILTER (WHERE status = 'closed') as closed
      FROM tickets 
      WHERE created_at >= '2026-04-01' 
      AND created_at < '2026-05-01'
    `;
    
    const summaryResult = await client.query(summaryQuery);
    console.log(`\n📈 Final Status for April 2026:`);
    console.log(`   Open: ${summaryResult.rows[0].open}`);
    console.log(`   In Progress: ${summaryResult.rows[0].in_progress}`);
    console.log(`   Pending: ${summaryResult.rows[0].pending}`);
    console.log(`   Resolved: ${summaryResult.rows[0].resolved} ✅`);
    console.log(`   Closed: ${summaryResult.rows[0].closed}`);
    
  } catch (error) {
    await client.query('ROLLBACK');
    console.error('❌ Error:', error.message);
  } finally {
    client.release();
    await pool.end();
  }
}

resolveAprilTickets().catch(console.error);