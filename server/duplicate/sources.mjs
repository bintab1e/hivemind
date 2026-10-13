import { execFile } from 'node:child_process';
import { promisify } from 'node:util';

const timeoutMs = 20_000;
const maxResponseBytes = 2_000_000;
const agent = 'Hivemind-duplicate-check/1.0';
const exec = promisify(execFile);

const locations = {
  knfsd: {
    mail: 'https://lore.kernel.org/linux-nfs/new.atom',
    patches: 'https://patchwork.kernel.org/api/1.2/patches/?project=linux-nfs&per_page=100&order=-date',
    branch: ['nfsd-testing', 'nfsd-next', 'nfsd-fixes'].map(ref =>
      `https://git.kernel.org/pub/scm/linux/kernel/git/cel/linux.git/atom/?h=${ref}`),
  },
  'NFS-Ganesha': {
    mail: 'https://lists.nfs-ganesha.org/archives/api/list/devel@lists.nfs-ganesha.org/threads/?format=json',
    branch: 'https://api.github.com/repos/nfs-ganesha/nfs-ganesha/commits?sha=next&per_page=100',
  },
  libnfs: {
    mail: 'https://groups.google.com/g/libnfs',
    branch: 'https://api.github.com/repos/sahlberg/libnfs/commits?sha=master&per_page=100',
  },
};

function decodeXml(value) {
  return value.replace(/&(?:amp|lt|gt|quot|apos|#(\d+)|#x([a-f\d]+));/gi, (match, decimal, hex) => {
    if (decimal || hex) {
      const code = parseInt(decimal || hex, hex ? 16 : 10);
      return code >= 32 && code <= 0x10ffff ? String.fromCodePoint(code) : ' ';
    }
    return { '&amp;': '&', '&lt;': '<', '&gt;': '>', '&quot;': '"', '&apos;': "'" }[match.toLowerCase()] || match;
  });
}

function plain(value) {
  return decodeXml(value.replace(/<[^>]*>/g, ' ').replace(/\s+/g, ' ')).trim().slice(0, 12_000);
}

function atomEntries(xml, kind) {
  if (!/<feed\b/i.test(xml)) throw new Error('invalid_atom');
  const items = [];
  for (const match of xml.matchAll(/<entry\b[^>]*>([\s\S]*?)<\/entry>/gi)) {
    const body = match[1];
    const title = plain(/<title\b[^>]*>([\s\S]*?)<\/title>/i.exec(body)?.[1] || '');
    const rawUrl = /<link\b[^>]*\bhref=['"]([^'"]+)['"]/i.exec(body)?.[1];
    const url = rawUrl?.replace(/^http:\/\//i, 'https://');
    const content = /<content\b[^>]*>([\s\S]*?)<\/content>/i.exec(body)?.[1] || '';
    if (!title || !officialEvidenceUrl(kind === 'mail' ? 'knfsd' : 'knfsd', kind, url)) continue;
    items.push({ kind, title, url, text: plain(content), detail: null });
  }
  return items;
}

function groupTopics(html) {
  if (!/<html\b/i.test(html) || !html.includes('/g/libnfs/c/')) throw new Error('invalid_groups_page');
  const seen = new Set();
  const items = [];
  for (const match of html.matchAll(/href=['"](?:\.\/)?g\/libnfs\/c\/([A-Za-z0-9_-]{6,})['"]/g)) {
    if (seen.has(match[1])) continue;
    seen.add(match[1]);
    const around = html.slice(match.index, match.index + 800);
    items.push({ kind: 'mail', title: plain(around).slice(0, 250),
      url: `https://groups.google.com/g/libnfs/c/${match[1]}`, text: '', detail: 'groups' });
    if (items.length >= 60) break;
  }
  if (!items.length) throw new Error('empty_groups_page');
  return items;
}

export function officialEvidenceUrl(target, kind, value) {
  if (typeof value !== 'string') return false;
  let url;
  try { url = new URL(value); } catch { return false; }
  if (url.protocol !== 'https:' || url.username || url.password) return false;
  const p = url.pathname;
  if (target === 'knfsd') return kind === 'mail'
    ? url.hostname === 'lore.kernel.org' && /^\/(?:linux-nfs|r)\//.test(p) ||
      url.hostname === 'patchwork.kernel.org' && /^\/project\/linux-nfs\/(?:patch|series)\//.test(p)
    : url.hostname === 'git.kernel.org' && p === '/pub/scm/linux/kernel/git/cel/linux.git/commit/' && /^[a-f\d]{40,64}$/i.test(url.searchParams.get('id') || '');
  if (target === 'NFS-Ganesha') return kind === 'mail'
    ? url.hostname === 'lists.nfs-ganesha.org' && /^\/archives\/list\/devel@lists\.nfs-ganesha\.org\/(?:thread|message)\//.test(decodeURIComponent(p))
    : url.hostname === 'github.com' && /^\/nfs-ganesha\/nfs-ganesha\/commit\/[a-f\d]{40}$/i.test(p);
  if (target === 'libnfs') return kind === 'mail'
    ? url.hostname === 'groups.google.com' && /^\/g\/libnfs\/c\/[A-Za-z0-9_-]+/.test(p)
    : url.hostname === 'github.com' && /^\/sahlberg\/libnfs\/commit\/[a-f\d]{40}$/i.test(p);
  return false;
}

async function boundedText(url, expected, fetchImpl) {
  // curl handles the official archive hosts on the verification server where Node's HTTP client times out.
  if (fetchImpl === fetch) {
    let output;
    try {
      ({ stdout: output } = await exec('curl', ['--fail', '--silent', '--show-error', '--proto', '=https',
        '--max-time', String(timeoutMs / 1000), '--max-filesize', String(maxResponseBytes),
        '--user-agent', agent, '--header', `Accept: ${expected}`,
        '--write-out', '\nHIVEMIND_CONTENT_TYPE:%{content_type}\n', url],
      { encoding: 'utf8', timeout: timeoutMs + 1000, maxBuffer: maxResponseBytes + 1000 }));
    } catch { throw new Error('source_unavailable'); }
    const marker = '\nHIVEMIND_CONTENT_TYPE:';
    const at = output.lastIndexOf(marker);
    if (at < 0 || !output.slice(at + marker.length).toLowerCase().includes(expected.split('/')[1])) {
      throw new Error('source_content_type');
    }
    return output.slice(0, at);
  }
  const response = await fetchImpl(url, { headers: { 'User-Agent': agent, Accept: expected },
    signal: AbortSignal.timeout(timeoutMs), redirect: 'error' });
  if (!response.ok || !response.headers.get('content-type')?.toLowerCase().includes(expected.split('/')[1])) {
    throw new Error('source_unavailable');
  }
  const reader = response.body.getReader();
  const chunks = [];
  let size = 0;
  while (true) {
    const { done, value } = await reader.read();
    if (done) break;
    size += value.length;
    if (size > maxResponseBytes) { await reader.cancel(); throw new Error('source_too_large'); }
    chunks.push(value);
  }
  return Buffer.concat(chunks).toString('utf8');
}

async function json(url, fetchImpl) {
  const value = JSON.parse(await boundedText(url, 'application/json', fetchImpl));
  return value;
}

function githubCommits(rows, target) {
  if (!Array.isArray(rows)) throw new Error('invalid_github_response');
  return rows.flatMap(row => {
    const url = row?.html_url;
    const title = row?.commit?.message?.split('\n')[0]?.trim();
    if (!officialEvidenceUrl(target, 'branch', url) || !title) return [];
    return [{ kind: 'branch', title, url, text: row.commit.message.slice(0, 12_000),
      detail: `github:${target}:${row.sha}` }];
  });
}

async function ganeshaMail(fetchImpl) {
  const data = await json(locations['NFS-Ganesha'].mail, fetchImpl);
  if (!Array.isArray(data.results)) throw new Error('invalid_hyperkitty_response');
  return data.results.flatMap(row => {
    if (typeof row?.thread_id !== 'string' || !/^[A-Z2-7]{20,60}$/.test(row.thread_id) || typeof row.subject !== 'string') return [];
    return [{ kind: 'mail', title: row.subject.slice(0, 300),
      url: `https://lists.nfs-ganesha.org/archives/list/devel@lists.nfs-ganesha.org/thread/${row.thread_id}/`,
      text: '', detail: `hyperkitty:${row.thread_id}` }];
  });
}

function patchworkItems(rows) {
  if (!Array.isArray(rows)) throw new Error('invalid_patchwork_response');
  return rows.flatMap(item => {
    const url = item.web_url;
    if (!officialEvidenceUrl('knfsd', 'mail', url) || !Number.isInteger(item.id)) return [];
    return [{ kind: 'mail', title: String(item.name || '').slice(0, 300), url,
      text: '', detail: `patchwork:${item.id}` }];
  });
}

async function knfsdMail(fetchImpl) {
  const items = patchworkItems(await json(locations.knfsd.patches, fetchImpl));
  // Lore mirrors general list discussion but can block automated hosts. Patchwork remains the required source.
  try { items.push(...atomEntries(await boundedText(locations.knfsd.mail, 'application/atom+xml', fetchImpl), 'mail')); }
  catch { /* Keep the official patch archive result. */ }
  return [...new Map(items.map(item => [item.url, item])).values()];
}

export async function fetchProjectSources(target, fetchImpl = fetch) {
  if (!Object.hasOwn(locations, target)) throw new Error('invalid_target');
  const result = { mail: { ok: false, items: [] }, branch: { ok: false, items: [] } };
  try {
    if (target === 'knfsd') result.mail.items = await knfsdMail(fetchImpl);
    else if (target === 'NFS-Ganesha') result.mail.items = await ganeshaMail(fetchImpl);
    else result.mail.items = groupTopics(await boundedText(locations.libnfs.mail, 'text/html', fetchImpl));
    result.mail.ok = result.mail.items.length > 0;
  } catch { /* A failed official source must not be treated as a clean check. */ }
  try {
    if (target === 'knfsd') {
      const lists = await Promise.all(locations.knfsd.branch.map(url => boundedText(url, 'text/xml', fetchImpl)));
      result.branch.items = [...new Map(lists.flatMap(xml => atomEntries(xml, 'branch')).map(item => [item.url, item])).values()];
    } else result.branch.items = githubCommits(await json(locations[target].branch, fetchImpl), target);
    result.branch.ok = result.branch.items.length > 0;
  } catch { /* The daily run records a source failure. */ }
  return result;
}

export function publicCodeQuery(row) {
  const values = [row.file_path, ...(Array.isArray(row.code_refs) ? row.code_refs : [])]
    .filter(value => typeof value === 'string');
  for (const value of values) {
    const symbol = /\b(?:nfsd[0-9]*|nfs4|nfs3|svc|rpc|zdr|fsal)_[a-z_0-9]{4,}\b/i.exec(value)?.[0];
    if (symbol) return symbol.slice(0, 80);
  }
  for (const value of publicCodeReferences(row)) {
    const basename = /(?:^|\/)([a-z][a-z_0-9]{5,})\.(?:c|h)(?::\d+)?\b/i.exec(value)?.[1];
    if (basename) return basename.slice(0, 80);
  }
  return null;
}

export function publicCodeReferences(row) {
  const text = [row.file_path, ...(Array.isArray(row.code_refs) ? row.code_refs : []), row.report_excerpt]
    .filter(value => typeof value === 'string').join('\n');
  const prefix = row.target === 'knfsd' ? '(?:fs\\/(?:nfsd|nfs|nfs_common|lockd|exportfs)|net\\/sunrpc|include\\/(?:linux\\/sunrpc|uapi\\/linux\\/nfsd))'
    : row.target === 'NFS-Ganesha' ? 'src' : row.target === 'libnfs' ? '(?:lib|include|src)' : null;
  if (!prefix) return [];
  const paths = [...text.matchAll(new RegExp(`\\b${prefix}\\/[A-Za-z0-9_./+-]+\\.(?:c|h)\\b`, 'g'))]
    .map(match => match[0]).filter(value => !value.includes('..') && value.length <= 200);
  const symbols = [...text.matchAll(/\b(?:nfsd[0-9]*|nfs4|nfs3|svc|rpc|zdr|fsal)_[A-Za-z0-9_]{4,}\b/gi)]
    .map(match => match[0]).filter(value => value.length <= 100);
  return [...new Set([...paths, ...symbols])].slice(0, 30);
}

export async function searchHistoricalMail(target, row, fetchImpl = fetch) {
  const q = publicCodeQuery(row);
  if (!q) return [];
  if (target === 'knfsd') {
    const url = `https://patchwork.kernel.org/api/1.2/patches/?project=linux-nfs&per_page=50&order=-date&q=${encodeURIComponent(q)}`;
    const rows = await json(url, fetchImpl);
    return patchworkItems(rows);
  }
  if (target === 'NFS-Ganesha') {
    const search = `https://lists.nfs-ganesha.org/archives/search?mlist=devel%40lists.nfs-ganesha.org&q=${encodeURIComponent(q)}&sort=date-desc`;
    const html = await boundedText(search, 'text/html', fetchImpl);
    if (!/<html\b/i.test(html)) throw new Error('invalid_hyperkitty_search');
    const ids = [...new Set([...html.matchAll(/\/archives\/list\/devel(?:%40|@)lists\.nfs-ganesha\.org\/thread\/([A-Z2-7]{20,60})\//g)].map(match => match[1]))].slice(0, 30);
    return ids.map(id => ({ kind: 'mail', title: q,
      url: `https://lists.nfs-ganesha.org/archives/list/devel@lists.nfs-ganesha.org/thread/${id}/`,
      text: '', detail: `hyperkitty:${id}` }));
  }
  return [];
}

export async function searchHistoricalBranch(target, row, fetchImpl = fetch) {
  if (target === 'knfsd') return [];
  const filePath = publicCodeReferences(row).find(value => /\.(?:c|h)$/.test(value));
  if (typeof filePath !== 'string' || filePath.length > 200 ||
      !/^(?:src\/|lib\/|include\/)[a-zA-Z0-9_./+-]+\.(?:c|h)$/.test(filePath) ||
      filePath.split('/').some(part => part === '.' || part === '..')) return [];
  const repo = target === 'NFS-Ganesha' ? 'nfs-ganesha/nfs-ganesha' : target === 'libnfs' ? 'sahlberg/libnfs' : null;
  if (!repo) return [];
  const branch = target === 'NFS-Ganesha' ? 'next' : 'master';
  const rows = await json(`https://api.github.com/repos/${repo}/commits?sha=${branch}&path=${encodeURIComponent(filePath)}&per_page=50`, fetchImpl);
  return githubCommits(rows, target);
}

export function rankEvidence(row, items, limit = 8) {
  const terms = new Set([row.title, row.vulnerability_type, ...publicCodeReferences(row)]
    .filter(value => typeof value === 'string').join(' ').toLowerCase().match(/[a-z][a-z0-9_]{4,}/g) || []);
  const path = publicCodeReferences(row).find(value => /\.(?:c|h)$/.test(value))?.toLowerCase() || '';
  return items.map(item => {
    const text = `${item.title} ${item.text}`.toLowerCase();
    let score = path && text.includes(path) ? 10 : 0;
    for (const term of terms) if (text.includes(term)) score++;
    return { item, score };
  }).filter(row => row.score > 0).sort((a, b) => b.score - a.score)
    .slice(0, limit).map(row => row.item);
}

export async function hydrateEvidence(item, fetchImpl = fetch) {
  const target = item?.url?.includes('nfs-ganesha') ? 'NFS-Ganesha'
    : item?.url?.includes('/sahlberg/libnfs/') || item?.url?.includes('groups.google.com') ? 'libnfs' : 'knfsd';
  if (!item?.detail || !officialEvidenceUrl(target, item.kind, item.url)) return item;
  if (item.detail.startsWith('patchwork:')) {
    const id = Number(item.detail.slice(10));
    if (!Number.isSafeInteger(id) || id < 1) return item;
    const data = await json(`https://patchwork.kernel.org/api/1.2/patches/${id}/`, fetchImpl);
    return { ...item, text: `${data.content || ''}\n${data.diff || ''}`.slice(0, 14_000), detail: null };
  }
  if (item.detail.startsWith('hyperkitty:')) {
    const id = item.detail.slice(11);
    if (!/^[A-Z2-7]{20,60}$/.test(id)) return item;
    const url = `https://lists.nfs-ganesha.org/archives/api/list/devel@lists.nfs-ganesha.org/thread/${id}/emails/?format=json`;
    const data = await json(url, fetchImpl);
    const emails = Array.isArray(data) ? data : data.results;
    if (!Array.isArray(emails)) throw new Error('invalid_hyperkitty_email');
    const bodies = [];
    for (const email of emails.slice(0, 3)) {
      if (typeof email.message_id_hash !== 'string' || !/^[A-Z2-7]{20,60}$/.test(email.message_id_hash)) continue;
      const message = await json(`https://lists.nfs-ganesha.org/archives/api/list/devel@lists.nfs-ganesha.org/email/${email.message_id_hash}/?format=json`, fetchImpl);
      bodies.push(`${message.subject || ''}\n${message.content || ''}`);
    }
    return { ...item, text: bodies.join('\n').slice(0, 14_000), detail: null };
  }
  if (item.detail.startsWith('github:')) {
    const [, target, sha] = /^github:(NFS-Ganesha|libnfs):([a-f\d]{40})$/i.exec(item.detail) || [];
    if (!target || !sha) return item;
    const repo = target === 'NFS-Ganesha' ? 'nfs-ganesha/nfs-ganesha' : 'sahlberg/libnfs';
    const patch = await boundedText(`https://github.com/${repo}/commit/${sha}.patch`, 'text/plain', fetchImpl);
    if (!patch.startsWith('From ') || !patch.includes('diff --git ')) throw new Error('invalid_github_patch');
    return { ...item, text: patch.slice(0, 14_000), detail: null };
  }
  if (item.detail === 'groups') {
    const html = await boundedText(item.url, 'text/html', fetchImpl);
    if (!/<html\b/i.test(html)) throw new Error('invalid_groups_topic');
    return { ...item, text: plain(html).slice(0, 14_000), detail: null };
  }
  return item;
}
