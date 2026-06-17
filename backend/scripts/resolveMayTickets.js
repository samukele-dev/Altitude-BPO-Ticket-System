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
    console.log('🔍 Starting to resolve tickets from May 2026...');
    
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
        COUNT(*) FILTER (WHERE status = 'closed') as already_closed
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
    console.log(`   Already closed: ${stats.already_closed}`);
    
    if (stats.total_tickets === 0) {
      console.log('⚠️  No tickets found for May 2026');
      await client.query('ROLLBACK');
      return;
    }
    
    // Ask for confirmation
    console.log('\n⚠️  This will RESOLVE (not close) all non-resolved tickets from May 2026');
    console.log('Press Ctrl+C to cancel, or wait 5 seconds to continue...');
    await new Promise(resolve => setTimeout(resolve, 5000));
    
    // Update all May tickets to RESOLVED (not closed)
    const updateQuery = `
      UPDATE tickets 
      SET 
        status = 'resolved',
        resolved_at = CURRENT_TIMESTAMP,
        updated_at = CURRENT_TIMESTAMP
      WHERE created_at >= '2026-05-01' 
        AND created_at < '2026-06-01'
        AND status NOT IN ('resolved', 'closed')
    `;
    
    const updateResult = await client.query(updateQuery);
    const updatedCount = updateResult.rowCount;
    
    // Commit transaction
    await client.query('COMMIT');
    
    console.log('\n✅ Successfully resolved tickets!');
    console.log(`   Total tickets resolved: ${updatedCount}`);
    console.log(`   Already resolved: ${stats.already_resolved}`);
    console.log(`   Already closed: ${stats.already_closed}`);
    
    // Show updated statistics
    const finalCheck = await client.query(`
      SELECT 
        COUNT(*) FILTER (WHERE status = 'open') as still_open,
        COUNT(*) FILTER (WHERE status = 'in_progress') as still_in_progress,
        COUNT(*) FILTER (WHERE status = 'pending') as still_pending,
        COUNT(*) FILTER (WHERE status = 'resolved') as now_resolved,
        COUNT(*) FILTER (WHERE status = 'closed') as closed
      FROM tickets 
      WHERE created_at >= '2026-05-01' 
        AND created_at < '2026-06-01'
    `);
    
    console.log(`\n📈 Final Status for May 2026:`);
    console.log(`   Still open: ${finalCheck.rows[0].still_open}`);
    console.log(`   Still in progress: ${finalCheck.rows[0].still_in_progress}`);
    console.log(`   Still pending: ${finalCheck.rows[0].still_pending}`);
    console.log(`   Now resolved: ${finalCheck.rows[0].now_resolved}`);
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