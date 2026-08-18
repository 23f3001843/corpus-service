// api/build-corpus.js
const crypto = require('crypto');

// ---------- CRC32C (Castagnoli) ----------
const CRC32C_TABLE = (() => {
  const table = new Uint32Array(256);
  for (let n = 0; n < 256; n++) {
    let c = n;
    for (let k = 0; k < 8; k++) {
      c = (c & 1) ? (0x82F63B78 ^ (c >>> 1)) : (c >>> 1);
    }
    table[n] = c >>> 0;
  }
  return table;
})();

function crc32c(buf) {
  let crc = 0xFFFFFFFF;
  for (let i = 0; i < buf.length; i++) {
    crc = CRC32C_TABLE[(crc ^ buf[i]) & 0xFF] ^ (crc >>> 8);
  }
  return ((crc ^ 0xFFFFFFFF) >>> 0).toString(16).padStart(8, '0');
}

function sha256Hex(buf) {
  return crypto.createHash('sha256').update(buf).digest('hex');
}

// ---------- Byte comparison (UTF-8) ----------
function cmpBytes(a, b) {
  const ba = Buffer.from(a, 'utf8');
  const bb = Buffer.from(b, 'utf8');
  const len = Math.min(ba.length, bb.length);
  for (let i = 0; i < len; i++) {
    if (ba[i] !== bb[i]) return ba[i] - bb[i];
  }
  return ba.length - bb.length;
}

// ---------- Time parsing ----------
const TIME_RE = /^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(\.\d{1,3})?(Z|[+-]\d{2}:\d{2})$/;
const DAYS_IN_MONTH = [31,28,31,30,31,30,31,31,30,31,30,31];

function isLeap(y) { return (y % 4 === 0 && y % 100 !== 0) || y % 400 === 0; }

function parseTimeToUtcMillis(str) {
  if (typeof str !== 'string') return null;
  const m = TIME_RE.exec(str);
  if (!m) return null;
  const year = +m[1], month = +m[2], day = +m[3];
  const hour = +m[4], minute = +m[5], second = +m[6];
  const fracStr = m[7] ? m[7].slice(1) : '';
  const ms = fracStr ? Math.round(Number('0.' + fracStr) * 1000) : 0;
  const offsetStr = m[8];

  if (month < 1 || month > 12) return null;
  const maxDay = month === 2 && isLeap(year) ? 29 : DAYS_IN_MONTH[month - 1];
  if (day < 1 || day > maxDay) return null;
  if (hour > 23 || minute > 59 || second > 59) return null;

  let offsetMinutes = 0;
  if (offsetStr !== 'Z') {
    const sign = offsetStr[0] === '-' ? -1 : 1;
    const oh = +offsetStr.slice(1, 3);
    const om = +offsetStr.slice(4, 6);
    if (oh > 14 || om > 59) return null;
    if (oh === 14 && om !== 0) return null;
    offsetMinutes = sign * (oh * 60 + om);
  }

  const baseMs = Date.UTC(year, month - 1, day, hour, minute, second, ms);
  return baseMs - offsetMinutes * 60000;
}

function formatUtcMillis(ms) {
  const d = new Date(ms);
  const pad = (n, l = 2) => String(n).padStart(l, '0');
  return `${d.getUTCFullYear()}-${pad(d.getUTCMonth() + 1)}-${pad(d.getUTCDate())}T` +
    `${pad(d.getUTCHours())}:${pad(d.getUTCMinutes())}:${pad(d.getUTCSeconds())}.` +
    `${pad(d.getUTCMilliseconds(), 3)}Z`;
}

// ---------- Canonicalization ----------
function canonText(s) {
  return s.normalize('NFKC').toLowerCase().replace(/\p{White_Space}+/gu, ' ').trim();
}

function wordSet(s) {
  const matches = s.match(/[\p{L}\p{N}]+/gu) || [];
  return new Set(matches.map(w => w.toLowerCase()));
}

function jaccard(a, b) {
  if (a.size === 0 && b.size === 0) return 1;
  let inter = 0;
  for (const w of a) if (b.has(w)) inter++;
  const union = a.size + b.size - inter;
  return union === 0 ? 1 : inter / union;
}

// ---------- Row / object validation ----------
const URI_RE = /^gs:\/\/[^/]+\/.+$/;
const GEN_RE = /^\d+$/;
const CRC_RE = /^[0-9a-f]{8}$/;

function addCode(set, code) { set.add(code); }

function isPlainObject(v) {
  return typeof v === 'object' && v !== null && !Array.isArray(v);
}

function validateRowShape(row) {
  if (!isPlainObject(row)) return false;
  const keys = Object.keys(row).sort();
  const expected = ['entity', 'eventTime', 'id', 'revision', 'text'];
  if (keys.length !== 5 || !keys.every((k, i) => k === expected[i])) return false;
  if (typeof row.id !== 'string' || typeof row.entity !== 'string') return false;
  if (typeof row.eventTime !== 'string' || typeof row.text !== 'string') return false;
  if (typeof row.revision !== 'number' || !Number.isInteger(row.revision)) return false;
  if (row.revision < 0 || !Number.isSafeInteger(row.revision)) return false;
  return true;
}

function processObject(obj) {
  const codes = new Set();
  const uri = typeof obj?.uri === 'string' ? obj.uri : null;

  if (uri === null || !URI_RE.test(uri)) addCode(codes, 'URI_INVALID');

  const gen = obj?.generation;
  const fgen = obj?.fetchedGeneration;
  const genValid = typeof gen === 'string' && GEN_RE.test(gen);
  const fgenValid = typeof fgen === 'string' && GEN_RE.test(fgen);
  if (!genValid || !fgenValid) addCode(codes, 'GENERATION_INVALID');
  if (genValid && fgenValid && gen !== fgen) addCode(codes, 'GENERATION_MISMATCH');

  const crc = obj?.crc32c;
  const crcValid = typeof crc === 'string' && CRC_RE.test(crc);
  if (!crcValid) addCode(codes, 'CRC32C_INVALID');

  const content = obj?.content;
  const contentIsString = typeof content === 'string';

  if (crcValid && contentIsString) {
    const actual = crc32c(Buffer.from(content, 'utf8'));
    if (actual !== crc) addCode(codes, 'CRC32C_MISMATCH');
  }

  if (obj?.schemaId !== 'training-v1') addCode(codes, 'SCHEMA_INVALID');
  if (!contentIsString) addCode(codes, 'SCHEMA_INVALID');

  let rows = [];
  if (contentIsString) {
    const lines = content.split('\n').filter(l => l.trim().length > 0);
    if (lines.length === 0) {
      addCode(codes, 'SCHEMA_INVALID');
    } else {
      let jsonlBad = false;
      let shapeBad = false;
      for (const line of lines) {
        let parsed;
        try {
          parsed = JSON.parse(line);
        } catch {
          jsonlBad = true;
          continue;
        }
        if (!validateRowShape(parsed)) {
          shapeBad = true;
          continue;
        }
        rows.push(parsed);
      }
      if (jsonlBad) addCode(codes, 'JSONL_INVALID');
      if (shapeBad) addCode(codes, 'SCHEMA_INVALID');
    }
  }

  return { uri, codes, rows, obj, accepted: codes.size === 0 };
}

// ---------- Main handler ----------
module.exports = async (req, res) => {
  if (req.method !== 'POST') {
    res.status(404).json({ error: 'INVALID_INPUT' });
    return;
  }

  const body = req.body && typeof req.body === 'object' ? req.body : {};
  const policy = body.policy;
  const objects = body.objects;

  if (!isPlainObject(policy) || !Array.isArray(objects)) {
    res.status(400).json({ error: 'INVALID_INPUT' });
    return;
  }

  const rejectedObjects = [];
  const lineage = [];
  const acceptedRows = []; // { id, entity, eventTime(ms), revision, text, sourceEntity, sourceText }

  for (const obj of objects) {
    const result = processObject(obj);
    if (!result.accepted) {
      rejectedObjects.push({ uri: result.uri, reasonCodes: sortDedup([...result.codes]) });
      continue;
    }
    lineage.push({
      uri: result.uri,
      generation: obj.generation,
      crc32c: obj.crc32c,
      schemaId: obj.schemaId,
    });
    for (const r of result.rows) {
      const utcMs = parseTimeToUtcMillis(r.eventTime);
      acceptedRows.push({
        id: r.id,
        rawEntity: r.entity,
        rawText: r.text,
        entity: canonText(r.entity),
        text: canonText(r.text),
        eventTimeMs: utcMs,
        revision: r.revision,
      });
    }
  }

  // ---- Dedup by [entity, eventTime(normalized), text] ----
  const rejectedRows = [];
  const groups = new Map();
  for (const row of acceptedRows) {
    const timeKey = row.eventTimeMs === null ? `INVALID:${row.id}` : formatUtcMillis(row.eventTimeMs);
    const key = JSON.stringify([row.entity, timeKey, row.text]);
    if (!groups.has(key)) groups.set(key, []);
    groups.get(key).push(row);
  }

  let survivors = [];
  for (const [, group] of groups) {
    if (group.length === 1) {
      survivors.push(group[0]);
      continue;
    }
    let winner = group[0];
    for (const cand of group.slice(1)) {
      if (cand.revision > winner.revision) winner = cand;
      else if (cand.revision === winner.revision && cmpBytes(cand.id, winner.id) < 0) winner = cand;
    }
    for (const loser of group) {
      if (loser !== winner) rejectedRows.push({ id: loser.id, codes: new Set(['DUPLICATE']) });
    }
    survivors.push(winner);
  }

  // ---- Policy validation ----
  const minMs = parseTimeToUtcMillis(policy.minTime);
  const maxMs = parseTimeToUtcMillis(policy.maxTime);
  const thresh = policy.contaminationThreshold;
  const threshValid = typeof thresh === 'number' && Number.isFinite(thresh) && thresh >= 0 && thresh <= 1;
  const policyValid = minMs !== null && maxMs !== null && minMs <= maxMs && threshValid;

  let windowed = [];
  for (const row of survivors) {
    if (!policyValid) {
      rejectedRows.push({ id: row.id, codes: new Set(['POLICY_INVALID']) });
      continue;
    }
    if (row.eventTimeMs === null || row.eventTimeMs < minMs || row.eventTimeMs > maxMs) {
      rejectedRows.push({ id: row.id, codes: new Set(['OUT_OF_WINDOW']) });
      continue;
    }
    windowed.push(row);
  }

  // ---- Split assignment ----
  const train = [], validation = [], test = [];
  for (const row of windowed) {
    const hash = crypto.createHash('sha256').update(Buffer.from(row.entity, 'utf8')).digest();
    const bucket = hash[0] % 10;
    if (bucket <= 5) train.push(row);
    else if (bucket <= 7) validation.push(row);
    else test.push(row);
  }

  // ---- Contamination check ----
  const trainWordSets = train.map(r => wordSet(r.text));
  function isContaminated(row) {
    const ws = wordSet(row.text);
    for (const tws of trainWordSets) {
      if (jaccard(ws, tws) >= thresh) return true;
    }
    return false;
  }

  const finalValidation = [];
  const finalTest = [];
  for (const row of validation) {
    if (isContaminated(row)) rejectedRows.push({ id: row.id, codes: new Set(['TRAIN_CONTAMINATION']) });
    else finalValidation.push(row);
  }
  for (const row of test) {
    if (isContaminated(row)) rejectedRows.push({ id: row.id, codes: new Set(['TRAIN_CONTAMINATION']) });
    else finalTest.push(row);
  }

  // ---- Serialize a split ----
  function serializeSplit(rows) {
    const sorted = rows.slice().sort((a, b) => {
      const c = cmpBytes(a.id, b.id);
      if (c !== 0) return c;
      return cmpBytes(compactRow(a), compactRow(b));
    });
    let buf = Buffer.alloc(0);
    const jsonRows = [];
    for (const r of sorted) {
      const line = compactRow(r) + '\n';
      buf = Buffer.concat([buf, Buffer.from(line, 'utf8')]);
      jsonRows.push(JSON.parse(compactRow(r)));
    }
    return { rows: jsonRows, digest: sha256Hex(buf) };
  }

  function compactRow(r) {
    return JSON.stringify({
      id: r.id,
      entity: r.entity,
      eventTime: formatUtcMillis(r.eventTimeMs),
      revision: r.revision,
      text: r.text,
    });
  }

  const trainSer = serializeSplit(train);
  const valSer = serializeSplit(finalValidation);
  const testSer = serializeSplit(finalTest);

  // ---- Merge rejected row codes (a row could theoretically get multiple codes over stages, but our pipeline stops at first rejection) ----
  const rejectedRowMap = new Map();
  for (const rr of rejectedRows) {
    if (!rejectedRowMap.has(rr.id)) rejectedRowMap.set(rr.id, new Set());
    for (const c of rr.codes) rejectedRowMap.get(rr.id).add(c);
  }
  const finalRejectedRows = [...rejectedRowMap.entries()]
    .map(([id, codes]) => ({ id, reasonCodes: sortDedup([...codes]) }))
    .sort((a, b) => {
      const c = cmpBytes(a.id, b.id);
      if (c !== 0) return c;
      return cmpBytes(JSON.stringify(a), JSON.stringify(b));
    });

  const finalRejectedObjects = rejectedObjects
    .slice()
    .sort((a, b) => {
      const au = a.uri === null ? '' : a.uri;
      const bu = b.uri === null ? '' : b.uri;
      const c = cmpBytes(au, bu);
      if (c !== 0) return c;
      return cmpBytes(JSON.stringify(a), JSON.stringify(b));
    });

  const finalLineage = lineage
    .slice()
    .sort((a, b) => {
      const c = cmpBytes(a.uri, b.uri);
      if (c !== 0) return c;
      return cmpBytes(JSON.stringify(a), JSON.stringify(b));
    });

  res.status(200).json({
    splits: { train: trainSer.rows, validation: valSer.rows, test: testSer.rows },
    rejectedObjects: finalRejectedObjects,
    rejectedRows: finalRejectedRows,
    digests: { train: trainSer.digest, validation: valSer.digest, test: testSer.digest },
    lineage: finalLineage,
  });
};

function sortDedup(arr) {
  const uniq = [...new Set(arr)];
  uniq.sort((a, b) => cmpBytes(a, b));
  return uniq;
}
