const { Pool } = require('pg');
require('dotenv').config();

// Database connection
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
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
    console.log(`   Already closed: ${stats.already_closed}`);
    
    if (stats.total_tickets === 0) {
      console.log('⚠️  No tickets found for May 2026');
      await client.query('ROLLBACK');
      return;
    }
    
    // Ask for confirmation
    console.log('\n⚠️  This will resolve all non-closed tickets from May 2026');
    console.log('Press Ctrl+C to cancel, or wait 5 seconds to continue...');
    await new Promise(resolve => setTimeout(resolve, 5000));
    
    // Update all May tickets to resolved/closed
    const updateQuery = `
      UPDATE tickets 
      SET 
        status = 'closed',
        resolved_at = CURRENT_TIMESTAMP,
        updated_at = CURRENT_TIMESTAMP,
        resolution_note = 'Auto-resolved: All May 2026 tickets resolved as part of bulk cleanup'
      WHERE created_at >= '2026-05-01' 
        AND created_at < '2026-06-01'
        AND status != 'closed'
      RETURNING 
        id, 
        ticket_number,
        status as old_status,
        title
    `;
    
    const updateResult = await client.query(updateQuery);
    const updatedCount = updateResult.rowCount;
    
    // Create activity log entries for each resolved ticket
    if (updatedCount > 0) {
      for (const ticket of updateResult.rows) {
        await client.query(`
          INSERT INTO ticket_activities (
            ticket_id,
            action,
            description,
            created_by,
            created_at
          ) VALUES ($1, $2, $3, $4, CURRENT_TIMESTAMP)
        `, [
          ticket.id,
          'status_change',
          `Ticket auto-resolved: Status changed from ${ticket.old_status} to closed (May 2026 bulk resolution)`,
          'system'
        ]);
      }
    }
    
    // Commit transaction
    await client.query('COMMIT');
    
    console.log('\n✅ Successfully resolved tickets!');
    console.log(`   Total tickets resolved: ${updatedCount}`);
    console.log(`   Already closed: ${stats.already_closed}`);
    
    // Show updated statistics
    const finalCheck = await client.query(`
      SELECT 
        COUNT(*) FILTER (WHERE status = 'open') as still_open,
        COUNT(*) FILTER (WHERE status = 'closed') as now_closed
      FROM tickets 
      WHERE created_at >= '2026-05-01' 
        AND created_at < '2026-06-01'
    `);
    
    console.log(`\n📈 Final Status for May 2026:`);
    console.log(`   Still open: ${finalCheck.rows[0].still_open}`);
    console.log(`   Now closed: ${finalCheck.rows[0].now_closed}`);
    
  } catch (error) {
    await client.query('ROLLBACK');
    console.error('❌ Error resolving tickets:', error.message);
    throw error;
  } finally {
    client.release();
    await pool.end();
  }
}

// Run the script
resolveMayTickets().catch(console.error);