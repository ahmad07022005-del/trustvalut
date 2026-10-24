'use strict';

const path = require('path');

/** Resolve a storage name and reject paths outside the configured directory. */
function containedPath(rootDir, storageName) {
  const root = path.resolve(rootDir);
  const candidate = path.resolve(root, storageName);
  if (candidate !== root && !candidate.startsWith(`${root}${path.sep}`)) {
    throw new Error('Resolved path escapes storage directory');
  }
  return candidate;
}

module.exports = { containedPath };
