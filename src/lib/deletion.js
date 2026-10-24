'use strict';

const fs = require('fs');
const { containedPath } = require('./paths');

function reconcilePendingDeletions(db, uploadsDir, persist) {
  const rows = db.exec("SELECT id, storage_name FROM documents WHERE deletion_state='pending'");
  if (!rows.length) return { attempted: 0, completed: 0, failed: 0 };
  let completed = 0; let failed = 0;
  for (const [id, storageName] of rows[0].values) {
    try {
      const filePath = containedPath(uploadsDir, storageName);
      if (fs.existsSync(filePath)) fs.unlinkSync(filePath);
      db.run("UPDATE documents SET deletion_state='deleted', is_deleted=1, deletion_error=NULL, deleted_at=COALESCE(deleted_at, strftime('%Y-%m-%dT%H:%M:%fZ','now')) WHERE id=?", [id]);
      completed++;
    } catch (err) {
      db.run('UPDATE documents SET deletion_attempts=deletion_attempts+1, deletion_error=? WHERE id=?', [String(err.message).slice(0, 200), id]);
      failed++;
    }
  }
  persist();
  return { attempted: completed + failed, completed, failed };
}

module.exports = { reconcilePendingDeletions };
