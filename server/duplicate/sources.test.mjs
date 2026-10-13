import test from 'node:test';
import assert from 'node:assert/strict';
import { fetchProjectSources, hydrateEvidence, officialEvidenceUrl, publicCodeQuery, publicCodeReferences, rankEvidence,
  searchHistoricalMail, searchHistoricalBranch } from './sources.mjs';

const row = { target: 'knfsd', title: 'PRIVATE exploit title',
  report_excerpt: 'PRIVATE report: fs/nfsd/nfs4state.c:42 calls nfsd4_open before validation',
  file_path: null, code_refs: [] };

test('public search sends only an extracted source identifier, never the private report or title', async () => {
  const requested = [];
  const fetchImpl = async url => {
    requested.push(url);
    return new Response('[]', { headers: { 'Content-Type': 'application/json' } });
  };
  assert.deepEqual(publicCodeReferences(row), ['fs/nfsd/nfs4state.c', 'nfsd4_open']);
  assert.equal(publicCodeQuery(row), 'nfs4state');
  await searchHistoricalMail('knfsd', row, fetchImpl);
  assert.equal(requested.length, 1);
  assert.match(requested[0], /q=nfs4state/);
  assert.doesNotMatch(requested[0], /PRIVATE|exploit|report|before.validation/);
});

test('official Patchwork JSON remains usable when Lore responds with an HTML challenge', async () => {
  const sha = 'a'.repeat(40);
  const atom = `<feed><entry><title>nfsd lifetime fix</title><link href='https://git.kernel.org/pub/scm/linux/kernel/git/cel/linux.git/commit/?id=${sha}'/><content type='text'>Fix fs/nfsd/nfs4state.c reference lifetime.</content></entry></feed>`;
  const fetchImpl = async url => {
    if (url.includes('patchwork.kernel.org')) return new Response(JSON.stringify([{ id: 42,
      name: 'nfsd lifetime fix', web_url: 'https://patchwork.kernel.org/project/linux-nfs/patch/abc/' }]),
    { headers: { 'Content-Type': 'application/json' } });
    if (url.includes('lore.kernel.org')) return new Response('<html>challenge</html>', { headers: { 'Content-Type': 'text/html' } });
    return new Response(atom, { headers: { 'Content-Type': 'text/xml' } });
  };
  const result = await fetchProjectSources('knfsd', fetchImpl);
  assert.equal(result.mail.ok, true);
  assert.equal(result.mail.items.length, 1);
  assert.equal(result.branch.ok, true);
  assert.equal(result.branch.items[0].text.includes('nfs4state.c'), true);
});

test('HyperKitty and GitHub details supply actual message and patch text', async () => {
  const id = 'A'.repeat(32);
  const sha = 'b'.repeat(40);
  const fetchImpl = async url => {
    if (url.includes('/threads/')) return new Response(JSON.stringify({ results: [{ thread_id: id, subject: 'FSAL fix' }] }),
      { headers: { 'Content-Type': 'application/json' } });
    if (url.includes('/thread/') && url.includes('/emails/')) return new Response(JSON.stringify({ results: [{ message_id_hash: id }] }),
      { headers: { 'Content-Type': 'application/json' } });
    if (url.includes('/email/')) return new Response(JSON.stringify({ subject: 'FSAL fix', content: 'Actual root cause in src/FSAL/handler.c' }),
      { headers: { 'Content-Type': 'application/json' } });
    if (url.endsWith(`/commit/${sha}.patch`)) return new Response('From 123 Mon Sep 17 00:00:00 2001\nSubject: fix\n\ndiff --git a/src/FSAL/handler.c b/src/FSAL/handler.c\n@@ -1 +1 @@\n-old\n+new',
      { headers: { 'Content-Type': 'text/plain' } });
    return new Response(JSON.stringify([{ sha, html_url: `https://github.com/nfs-ganesha/nfs-ganesha/commit/${sha}`,
      commit: { message: 'Fix reference in FSAL' } }]), { headers: { 'Content-Type': 'application/json' } });
  };
  const result = await fetchProjectSources('NFS-Ganesha', fetchImpl);
  assert.equal(result.mail.ok, true);
  assert.equal(result.branch.ok, true);
  assert.match((await hydrateEvidence(result.mail.items[0], fetchImpl)).text, /Actual root cause/);
  assert.match((await hydrateEvidence(result.branch.items[0], fetchImpl)).text, /@@ -1/);
});

test('branch history search uses an extracted public path only', async () => {
  const requested = [];
  const fetchImpl = async url => {
    requested.push(url);
    return new Response('[]', { headers: { 'Content-Type': 'application/json' } });
  };
  await searchHistoricalBranch('NFS-Ganesha', { target: 'NFS-Ganesha', title: 'PRIVATE title',
    report_excerpt: 'PRIVATE text src/Protocols/NFS/nfs4_op_open.c:80', file_path: null, code_refs: [] }, fetchImpl);
  assert.equal(requested.length, 1);
  assert.match(requested[0], /path=src%2FProtocols%2FNFS%2Fnfs4_op_open.c/);
  assert.doesNotMatch(requested[0], /PRIVATE/);
});

test('only official project evidence URLs are accepted', () => {
  assert.equal(officialEvidenceUrl('knfsd', 'mail', 'https://lore.kernel.org/r/patch-id/'), true);
  assert.equal(officialEvidenceUrl('knfsd', 'branch',
    `https://git.kernel.org/pub/scm/linux/kernel/git/cel/linux.git/commit/?id=${'a'.repeat(40)}`), true);
  assert.equal(officialEvidenceUrl('knfsd', 'mail', 'https://attacker.example/linux-nfs/patch'), false);
  assert.equal(officialEvidenceUrl('libnfs', 'branch', `https://github.com/sahlberg/libnfs/commit/${'a'.repeat(40)}`), true);
  const ranked = rankEvidence(row, [{ kind: 'mail', title: 'nfsd4_open fix', text: '', url: 'a' },
    { kind: 'mail', title: 'unrelated storage', text: '', url: 'b' }]);
  assert.equal(ranked[0].url, 'a');
});
