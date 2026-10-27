// Miner answers -> { severity, findings: [{ title, severity, detail? }], confidence }.
//
// One normalizer per miner response format, each written from real responses
// captured under test/fixtures/miner-responses/. Until a miner has one, its
// answers come back "unknown", which the policy turns into CAUTION: an
// unreadable answer must never pass as SAFE.

/** @type {Record<string, (result: unknown) => {severity: string, findings: object[], confidence: number}>} */
const NORMALIZERS = {};

const UNKNOWN = Object.freeze({ severity: "unknown", findings: [], confidence: 0 });

export function normalize(normalizerId, result) {
  const fn = NORMALIZERS[normalizerId];
  if (!fn) return UNKNOWN;
  try {
    return fn(result);
  } catch {
    return UNKNOWN;
  }
}
