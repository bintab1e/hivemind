const headings = ['Summary', 'Root cause', 'Reproduction environment', 'PoC', 'Impact analysis'];

function sections(report) {
  const matches = [...String(report || '').matchAll(/^## (Summary|Root cause|Reproduction environment|PoC|Impact analysis)\s*$/gm)];
  if (matches.length !== headings.length || matches.some((match, index) => match[1] !== headings[index] ||
      index === 0 && match.index !== 0)) return null;
  const parts = matches.map((match, index) => report.slice(match.index + match[0].length, matches[index + 1]?.index ?? report.length).trim());
  return parts.every(Boolean) ? parts : null;
}

export function canonicalArtifacts({ review, trustedSource, poc, kernelCommit }) {
  const normalized = review?.normalized;
  if (review?.verdict !== 'likely' || review.integrity?.verdict !== 'clear' || poc?.language !== 'c' ||
      poc.filename !== 'poc.c' || !/^[a-f0-9]{40}$/.test(kernelCommit || '') ||
      review.grounding?.source_commit !== kernelCommit || !normalized?.file_path || !sections(normalized.report)) return null;
  const source = trustedSource?.files?.find(file => file.path === normalized.file_path);
  const anchor = review.grounding.evidence?.find(item => item.path === normalized.file_path &&
    source?.lines?.some(line => line.number === item.line && line.text === item.text && line.text.trim()));
  const log = normalized.logs?.find(item => typeof item.content === 'string' && item.content.trim() &&
    Buffer.byteLength(item.content) <= 500_000);
  if (!anchor || !log || !poc.source?.trim() || !/\.c$/i.test(poc.original_name || '') ||
      !Array.isArray(normalized.code_refs) || !normalized.code_refs.length) return null;
  const snippet = source.lines.filter(line => Math.abs(line.number - anchor.line) <= 3)
    .sort((a, b) => a.number - b.number).map(line => line.text).join('\n');
  if (!normalized.report.includes(anchor.text.trim()) || !snippet.trim()) return null;
  const report = normalized.report.replace(/^## Reproduction environment\s*$/m,
    '## Reproduction environment\n\n서버 검증은 제출 자료의 정적 검토만 수행했습니다. PoC와 로그를 서버에서 실행하거나 재현하지 않았습니다.');
  const reproduction = [
    '# Reproduction', '',
    `Submitted kernel commit: \`${kernelCommit}\`.`,
    `Submitted NFS version: ${normalized.nfs_version ?? 'unknown / before NFS version decoding'}.`,
    'The original C PoC and submitted log were inspected statically. No server VM or PoC execution occurred.',
    `Original PoC: \`${poc.original_name}\`; normalized copy: \`poc.c\`.`,
    `Submitted build hint (not executed): ${JSON.stringify(poc.build_command || 'cc -o poc poc.c')}.`,
    poc.run_command ? `Submitted run hint (not executed): ${JSON.stringify(poc.run_command)}.` : 'No trustworthy run command was supplied.',
    'Target address and environment must be selected dynamically when a separate operator runs the PoC.',
    `Submitted evidence: \`${log.original_name}\` (not independently reproduced).`, '',
  ].join('\n');
  return {
    title: normalized.title,
    report: { filename: 'report.md', content: `${report.trim()}\n` },
    poc: { filename: 'poc.c', source_index: poc.source_index, source: poc.source },
    reproduction: { filename: 'reproduction.md', content: reproduction },
    log: { filename: 'evidence.log', content: log.content },
  };
}
