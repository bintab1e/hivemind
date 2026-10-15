export function normalizeRegistryOption(input) {
  if (typeof input !== 'string') return null;
  const settings = [...new Set(input.match(/\bCONFIG_[A-Z0-9_]+=(?:y|m|n)\b/g) || [])];
  if (settings.length) return settings.join(', ');
  const label = input.trim().replace(/[ \t]+/g, ' ');
  return label.length <= 40 && /^[A-Za-z][A-Za-z0-9_.+/-]*(?: [A-Za-z][A-Za-z0-9_.+/-]*){0,2}$/.test(label) &&
    /[A-Z0-9]/.test(label) && !/\b(?:port|listener|server|client|root|sudo|requires?|needs?|enabled|disabled)\b/i.test(label)
    ? label : null;
}
