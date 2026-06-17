const { Pool } = require('pg');
require('dotenv').config();

// Database connection with SSL for Render
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: {
    rejectUnauthorized: false  // Required for Render PostgreSQL
  }
});

async function resolveMayTickets() {
  const client = await pool.connect();
  
  try {
    console.log('🔍 Starting to RESOLVE all May 2026 tickets (including closed ones)...');
    
    // Start transaction
    await client.query('BEGIN');
    
    // First, check how many tickets will be affected
    const checkQuery = `
      SELECT 
        COUNT(*) as total_tickets,
        COUNT(*) FILTER (WHERE status = 'open') as open_tickets,
        COUNT(*) FILTER (WHERE status = 'in_progress') as in_progress_tickets,
        COUNT(*) FILTER (WHERE status = 'pending') as pending_tickets,
        COUNT(*) FILTER (WHERE status = 'resolved') as already_resolved,
        COUNT(*) FILTER (WHERE status = 'closed') as currently_closed
      FROM tickets 
      WHERE created_at >= '2026-05-01' 
        AND created_at < '2026-06-01'
    `;
    
    const checkResult = await client.query(checkQuery);
    const stats = checkResult.rows[0];
    
    console.log('📊 Ticket Statistics for May 2026:');
    console.log(`   Total tickets: ${stats.total_tickets}`);
    console.log(`   Open tickets: ${stats.open_tickets}`);
    console.log(`   In Progress: ${stats.in_progress_tickets}`);
    console.log(`   Pending: ${stats.pending_tickets}`);
    console.log(`   Already resolved: ${stats.already_resolved}`);
    console.log(`   Currently closed: ${stats.currently_closed}`);
    console.log(`   Tickets to be changed to resolved: ${stats.total_tickets - stats.already_resolved}`);
    
    if (stats.total_tickets === 0) {
      console.log('⚠️  No tickets found for May 2026');
      await client.query('ROLLBACK');
      return;
    }
    
    // Ask for confirmation
    console.log('\n⚠️  This will CHANGE ALL May 2026 tickets to "resolved" status (including closed ones)');
    console.log(`   ${stats.total_tickets - stats.already_resolved} tickets will be updated`);
    console.log('Press Ctrl+C to cancel, or wait 5 seconds to continue...');
    await new Promise(resolve => setTimeout(resolve, 5000));
    
    // Update ALL May tickets to RESOLVED (including closed ones)
    const updateQuery = `
      UPDATE tickets 
      SET 
        status = 'resolved',
        resolved_at = CURRENT_TIMESTAMP,
        updated_at = CURRENT_TIMESTAMP
      WHERE created_at >= '2026-05-01' 
        AND created_at < '2026-06-01'
        AND status != 'resolved'  -- Only exclude already resolved tickets
    `;
    
    const updateResult = await client.query(updateQuery);
    const updatedCount = updateResult.rowCount;
    
    // Commit transaction
    await client.query('COMMIT');
    
    console.log('\n✅ Successfully changed all tickets to RESOLVED!');
    console.log(`   Total tickets changed to resolved: ${updatedCount}`);
    console.log(`   Already resolved (unchanged): ${stats.already_resolved}`);
    
    // Show updated statistics
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
    console.error('❌ Error resolving tickets:', error.message);
    throw error;
  } finally {
    client.release();
    await pool.end();
  }
}

resolveMayTickets().catch(console.error);