import http from 'node:http';
import net from 'node:net';
import fs from 'node:fs';
import path from 'node:path';
import { execFileSync } from 'node:child_process';
import { HttpError, invalid } from './contract.mjs';
import { claimPrimitiveReview, claimSubmission, completePrimitiveReview, completeSubmission,
  failPrimitiveReview, failSubmission, heartbeatPrimitiveWorker, heartbeatWorker,
  progressSubmission } from './submissions.mjs';
import { listDuplicateCandidates, listInternalDuplicateReferences, recordDuplicateResult,
  recordInternalDuplicateResult } from './duplicate-registry.mjs';
import { claimPatchReview, completePatchReview, failPatchReview } from './patch-reviews.mjs';

function reply(res, status, value) {
  res.writeHead(status, { 'Content-Type': 'application/json; charset=utf-8', 'Cache-Control': 'no-store', 'X-Content-Type-Options': 'nosniff' });
  res.end(JSON.stringify(value));
}

async function inputJson(req) {
  if (!req.headers['content-type']?.startsWith('application/json')) invalid('Content-Type must be application/json', 415);
  let size = 0;
  const chunks = [];
  for await (const chunk of req) {
    size += chunk.length;
    if (size > 8_000_000) invalid('Verification result too large', 413);
    chunks.push(chunk);
  }
  try { return JSON.parse(Buffer.concat(chunks).toString('utf8')); }
  catch { invalid('Invalid JSON'); }
}

async function removeStaleSocket(socketPath) {
  let stat;
  try { stat = fs.lstatSync(socketPath); }
  catch (error) { if (error.code === 'ENOENT') return; throw error; }
  if (!stat.isSocket()) throw new Error(`Verifier socket path already contains a file: ${socketPath}`);
  const active = await new Promise(resolve => {
    const connection = net.createConnection(socketPath);
    connection.once('connect', () => { connection.destroy(); resolve(true); });
    connection.once('error', error => resolve(error.code !== 'ECONNREFUSED'));
  });
  if (active) throw new Error(`Verifier socket is already in use: ${socketPath}`);
  fs.unlinkSync(socketPath);
}

function allowVerifierUser(socketPath, user) {
  if (!user) return;
  if (!/^[a-z_][a-z0-9_-]*$/i.test(user)) throw new Error('Invalid verifier user');
  const uid = process.getuid?.();
  for (let directory = path.dirname(socketPath); directory !== path.dirname(directory); directory = path.dirname(directory)) {
    const stat = fs.statSync(directory);
    if (stat.mode & 0o001) continue;
    if (stat.uid !== uid) throw new Error(`Verifier user cannot traverse ${directory}`);
    execFileSync('setfacl', ['-m', `u:${user}:x`, directory], { stdio: 'ignore' });
  }
  execFileSync('setfacl', ['-m', `u:${user}:rw`, socketPath], { stdio: 'ignore' });
}

export async function startVerifierIpc(db, socketPath, verifierUser = null, dataDir = null) {
  if (!path.isAbsolute(socketPath) || path.resolve(socketPath) !== socketPath) throw new Error('Verifier socket path must be absolute and normalized');
  const parent = path.dirname(socketPath);
  fs.mkdirSync(parent, { recursive: true, mode: 0o700 });
  const parentStat = fs.lstatSync(parent);
  if (!parentStat.isDirectory() || parentStat.isSymbolicLink() || fs.realpathSync(parent) !== parent ||
      parentStat.uid !== process.getuid?.() || (parentStat.mode & 0o022)) {
    throw new Error('Verifier socket directory must be owned by the server and not writable by other users');
  }
  await removeStaleSocket(socketPath);
  const server = http.createServer(async (req, res) => {
    try {
      if (req.method === 'POST' && req.url === '/duplicate/candidates') {
        const body = await inputJson(req);
        if (!body || typeof body !== 'object' || Array.isArray(body) || Object.keys(body).length) invalid('Invalid duplicate candidates request');
        return reply(res, 200, { candidates: listDuplicateCandidates(db, dataDir) });
      }
      if (req.method === 'POST' && req.url === '/duplicate/result') {
        return reply(res, 200, recordDuplicateResult(db, await inputJson(req)));
      }
      if (req.method === 'POST' && req.url === '/duplicate/internal-candidates') {
        const body = await inputJson(req);
        if (!body || typeof body !== 'object' || Array.isArray(body) || Object.keys(body).length) invalid('Invalid internal duplicate candidates request');
        return reply(res, 200, { candidates: listDuplicateCandidates(db, dataDir),
          references: listInternalDuplicateReferences(db, dataDir) });
      }
      if (req.method === 'POST' && req.url === '/duplicate/internal-result') {
        return reply(res, 200, recordInternalDuplicateResult(db, await inputJson(req), dataDir));
      }
      if (req.method === 'POST' && req.url === '/patch/claim') {
        const body = await inputJson(req);
        if (!body || typeof body !== 'object' || Array.isArray(body) ||
            Object.keys(body).some(key => !['worker_id', 'supported_commits'].includes(key))) invalid('Invalid patch claim request');
        return reply(res, 200, { job: claimPatchReview(db, body.worker_id, body.supported_commits) });
      }
      if (req.method === 'POST' && req.url === '/patch/complete') {
        const body = await inputJson(req);
        if (!body || typeof body !== 'object' || Array.isArray(body) ||
            Object.keys(body).some(key => !['review_id', 'lease_token', 'status', 'result'].includes(key))) invalid('Invalid patch completion request');
        return reply(res, 200, completePatchReview(db, body.review_id, body.lease_token, body.status, body.result));
      }
      if (req.method === 'POST' && req.url === '/patch/fail') {
        const body = await inputJson(req);
        if (!body || typeof body !== 'object' || Array.isArray(body) ||
            Object.keys(body).some(key => !['review_id', 'lease_token', 'reason'].includes(key))) invalid('Invalid patch failure request');
        return reply(res, 200, failPatchReview(db, body.review_id, body.lease_token, body.reason));
      }
      if (req.method === 'POST' && req.url === '/claim') {
        const body = await inputJson(req);
        if (!body || typeof body !== 'object' || Array.isArray(body) ||
            Object.keys(body).some(key => key !== 'target_commit') ||
            (Object.hasOwn(body, 'target_commit') &&
              (typeof body.target_commit !== 'string' || !/^[a-f0-9]{40}$/.test(body.target_commit)))) invalid('Invalid claim request');
        return reply(res, 200, { job: claimSubmission(db, body.target_commit) });
      }
      if (req.method === 'POST' && req.url === '/progress') {
        const body = await inputJson(req);
        return reply(res, 200, progressSubmission(db, body?.submission_id, body?.phase, body?.lease_token));
      }
      if (req.method === 'POST' && req.url === '/heartbeat') {
        return reply(res, 200, heartbeatWorker(db, await inputJson(req)));
      }
      if (req.method === 'POST' && req.url === '/complete') {
        const body = await inputJson(req);
        if (!/^[a-f0-9]{64}$/.test(body?.submission_id || '')) invalid('Invalid submission_id');
        return reply(res, 200, completeSubmission(db, body.submission_id, body.result, body.lease_token));
      }
      if (req.method === 'POST' && req.url === '/fail') {
        const body = await inputJson(req);
        if (!/^[a-f0-9]{64}$/.test(body?.submission_id || '')) invalid('Invalid submission_id');
        return reply(res, 200, failSubmission(db, body.submission_id, body.reason, body.lease_token));
      }
      if (req.method === 'POST' && req.url === '/primitive/claim') {
        const body = await inputJson(req);
        if (!body || typeof body !== 'object' || Array.isArray(body) ||
            Object.keys(body).some(key => !['worker_id', 'supported_commits'].includes(key))) invalid('Invalid primitive claim request');
        return reply(res, 200, { job: claimPrimitiveReview(db, body.worker_id, body.supported_commits) });
      }
      if (req.method === 'POST' && req.url === '/primitive/heartbeat') {
        return reply(res, 200, heartbeatPrimitiveWorker(db, await inputJson(req)));
      }
      if (req.method === 'POST' && req.url === '/primitive/complete') {
        const body = await inputJson(req);
        return reply(res, 200, completePrimitiveReview(db, body?.finding_id, body?.summary, body?.lease_token));
      }
      if (req.method === 'POST' && req.url === '/primitive/fail') {
        const body = await inputJson(req);
        return reply(res, 200, failPrimitiveReview(db, body?.finding_id, body?.reason, body?.lease_token));
      }
      return reply(res, 404, { error: 'Not found' });
    } catch (error) {
      const status = error instanceof HttpError ? error.status : 500;
      if (status === 500) console.error('Verifier IPC:', error);
      reply(res, status, { error: status === 500 ? 'Internal server error' : error.message });
    }
  });
  await new Promise((resolve, reject) => { server.once('error', reject); server.listen(socketPath, resolve); });
  try {
    fs.chmodSync(socketPath, 0o600);
    allowVerifierUser(socketPath, verifierUser);
  } catch (error) {
    await new Promise(resolve => server.close(resolve));
    try { fs.unlinkSync(socketPath); }
    catch (cleanupError) { if (cleanupError.code !== 'ENOENT') console.error('Verifier socket cleanup:', cleanupError); }
    throw error;
  }
  server.on('close', () => { try { fs.unlinkSync(socketPath); } catch (error) { if (error.code !== 'ENOENT') console.error('Verifier socket cleanup:', error); } });
  return server;
}
