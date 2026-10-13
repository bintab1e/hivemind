import path from 'node:path';

const headings = ['Summary', 'Root cause', 'Reproduction environment', 'PoC', 'Impact analysis'];

function sections(report) {
  const matches = [...String(report || '').matchAll(/^## (Summary|Root cause|Reproduction environment|PoC|Impact analysis)\s*$/gim)];
  if (matches.length !== headings.length || matches.some((match, index) => match[1].toLowerCase() !== headings[index].toLowerCase())) return null;
  const parts = matches.map((match, index) => report.slice(match.index + match[0].length, matches[index + 1]?.index ?? report.length).trim());
  return parts.every(Boolean) ? Object.fromEntries(headings.map((heading, index) => [heading, parts[index]])) : null;
}

function safeProse(value) {
  return String(value || '').replace(/```[\s\S]*?```|~~~[\s\S]*?~~~/g, '').trim().replace(/^#{1,6}\s+/gm, '');
}

function relevantKasanLog(serial, traceLine) {
  const headers = [...serial.matchAll(/^[^\r\n]*BUG:\s*KASAN:[^\r\n]*/gim)];
  for (let index = 0; index < headers.length; index += 1) {
    const log = serial.slice(headers[index].index, headers[index + 1]?.index ?? serial.length).slice(0, 500_000).trim();
    if (log.split(/\r?\n/).some(line => line.trim() === traceLine?.trim()) && /\b(?:Read|Write) of size\s+\d+\b/i.test(log)) {
      return log;
    }
  }
  return null;
}

function normalizedTitle(title, filePath, log) {
  const candidate = String(title || '').replace(/^\s*#+\s*/, '').replace(/[\r\n\t]+/g, ' ').replace(/\s+/g, ' ').trim();
  if (candidate.length >= 8 && !/^(?:(?:nfs|knfsd)\s+)?(?:candidate|test|bug|issue|vulnerability|untitled|example|poc|취약점|예시)(?:\s*\d+)?$/i.test(candidate)) return candidate;
  const fault = /BUG:\s*KASAN:\s*([^\r\n]+)/i.exec(log)?.[1]?.replace(/\s+in\s+.*$/, '').trim() || 'KASAN finding';
  const access = /\bWrite of size\s+\d+\b/i.test(log) ? 'write' : 'read';
  return `${path.posix.basename(filePath)} ${fault} ${access}`.slice(0, 300);
}

export function canonicalArtifacts({ review, trustedSource, poc, serverSerial, kernelCommit, nfsVersion }) {
  const normalized = review?.normalized;
  const relevance = review?.relevance;
  if (review?.verdict !== 'likely' || relevance?.verdict !== 'supports' || poc?.language !== 'c' || poc.filename !== 'poc.c' ||
      !normalized?.file_path || !/^[a-f0-9]{40}$/.test(kernelCommit || '') ||
      !['3', '4', '4.1', '4.2'].includes(nfsVersion) || typeof serverSerial !== 'string') return null;
  const source = trustedSource?.files?.find(file => file.path === normalized.file_path);
  const anchor = review.grounding?.evidence?.find(item => item.path === normalized.file_path && item.line === relevance.source_line &&
    source?.lines?.some(line => line.number === item.line && line.text === item.text && line.text.trim()));
  const pocLine = poc.source?.split(/\r?\n/)[relevance.poc_line - 1];
  const log = relevantKasanLog(serverSerial, relevance.trace_line);
  if (!anchor || !pocLine?.trim() || !log || relevance.source_path !== normalized.file_path ||
      review.grounding?.source_commit !== kernelCommit) return null;

  const title = normalizedTitle(normalized.title, normalized.file_path, log);
  const reviewed = sections(normalized.report);
  const read = /\bRead of size\s+\d+\b/i.test(log);
  const write = /\bWrite of size\s+\d+\b/i.test(log);
  const impacts = [read && 'KASAN Read', write && 'KASAN Write'].filter(Boolean);
  const sourceLines = source.lines.filter(line => Math.abs(line.number - anchor.line) <= 3).sort((a, b) => a.number - b.number);
  const snippet = sourceLines.map(line => line.text).join('\n');
  const sourceReference = `${normalized.file_path}:${anchor.line}`;
  const mountSource = nfsVersion === '3' ? '10.77.0.1:/srv/export' : '10.77.0.1:/';
  const mountOptions = `vers=${nfsVersion},proto=tcp${nfsVersion === '3' ? ',nolock' : ''}`;
  const prose = {
    Summary: [`**${title}**`, safeProse(reviewed?.Summary || review.reason), `검증 결과: 원본 C PoC 시작 후 서버 VM에서 ${impacts.join(', ')} 보고가 관찰되었습니다.`].join('\n\n'),
    'Root cause': [safeProse(reviewed?.['Root cause'] || normalized.report), `검증한 커널 소스 조각 (${sourceReference}):`, '```c', snippet, '```', `정적 검토의 소스 앵커 ${sourceReference}와 PoC 이후 KASAN 스택 프레임을 연결했습니다.`].join('\n\n'),
    'Reproduction environment': [`QEMU 서버 VM과 클라이언트 VM, 커널 커밋 \`${kernelCommit}\`.`, `클라이언트는 \`${mountSource}\`를 \`/mnt/nfs\`에 \`${mountOptions}\`로 마운트했습니다.`, '서버 VM은 PoC 시작 전 깨끗한 기준선에서 시작했습니다.'].join('\n\n'),
    PoC: [safeProse(reviewed?.PoC || ''), `원본 제출 C 파일을 \`poc.c\`로 보존하고 클라이언트 VM에서 \`gcc -O0 -g -o /tmp/hivemind-poc /mnt/job/poc.c\`로 빌드했습니다.`, '클라이언트 VM에서 `/tmp/hivemind-poc 10.77.0.1 /mnt/nfs`를 실행한 뒤 서버 VM serial에서 KASAN 보고를 수집했습니다.', `검증 시 연결된 PoC 코드 (${poc.filename}:${relevance.poc_line}):`, '```c', pocLine.trim(), '```'].filter(Boolean).join('\n\n'),
    'Impact analysis': [`이번 2VM 재현에서 확인된 영향: **${impacts.join(', ')}**.`, 'Controlled Read/Write, LPE, RCE, Info Leak은 이 재현만으로 확인되지 않았습니다.'].join('\n\n'),
  };
  const report = `${headings.map(heading => `## ${heading}\n\n${prose[heading]}`).join('\n\n')}\n`;
  const reproduction = [
    '# Reproduction', '',
    `Kernel commit: \`${kernelCommit}\``,
    'Topology: isolated QEMU server and client VMs; server address `10.77.0.1`.',
    `NFS mount: \`mount -t nfs -o ${mountOptions} ${mountSource} /mnt/nfs\`.`,
    'Compile in the client VM: `gcc -O0 -g -o /tmp/hivemind-poc /mnt/job/poc.c`.',
    'Run in the client VM: `/tmp/hivemind-poc 10.77.0.1 /mnt/nfs`.',
    `Observed after PoC start: ${impacts.join(', ')} in the server VM serial output.`,
    'Evidence: `kasan.log`.', '',
  ].join('\n');
  return {
    title,
    report: { filename: 'report.md', content: report },
    poc: { filename: 'poc.c', source_index: poc.source_index, source: poc.source },
    reproduction: { filename: 'reproduction.md', content: reproduction },
    log: { filename: 'kasan.log', content: log },
  };
}
