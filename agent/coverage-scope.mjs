import fs from 'node:fs/promises';
import path from 'node:path';

export async function buildCoverageScope(repoRoot, prefixes) {
  const files = new Set();
  const queued = [];
  const missingIncludes = new Set();
  const add = name => {
    const normalized = path.posix.normalize(name.replaceAll('\\', '/'));
    if (normalized.startsWith('../') || files.has(normalized)) return;
    files.add(normalized);
    if (/\.[ch]$/.test(normalized)) queued.push(normalized);
  };
  const walk = async directory => {
    for (const entry of await fs.readdir(path.join(repoRoot, directory), { withFileTypes: true })) {
      const name = path.posix.join(directory, entry.name);
      if (entry.isDirectory()) await walk(name);
      else if (entry.isFile()) add(name);
    }
  };
  for (const prefix of prefixes) await walk(prefix.replace(/\/$/, ''));
  for (let index = 0; index < queued.length; index++) {
    const source = queued[index];
    const text = await fs.readFile(path.join(repoRoot, source), 'utf8');
    for (const match of text.matchAll(/^\s*#\s*include\s*([<"])([^">]+)[">]/gm)) {
      const name = match[2];
      const candidates = match[1] === '"' ? [path.posix.join(path.posix.dirname(source), name)] : [];
      candidates.push(path.posix.join('include', name), path.posix.join('include/uapi', name), name);
      let found = false;
      for (const candidate of candidates) {
        if ((await fs.stat(path.join(repoRoot, candidate)).catch(() => null))?.isFile()) {
          add(candidate);
          found = true;
          break;
        }
      }
      if (!found) missingIncludes.add(name);
    }
  }
  return { files, missingIncludes };
}
