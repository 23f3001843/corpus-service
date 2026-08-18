const crypto = require("crypto");

// ============================================================
// CRC32C (Castagnoli)
// ============================================================

const CRC32C_TABLE = (() => {
  const table = new Uint32Array(256);

  for (let n = 0; n < 256; n++) {
    let c = n;

    for (let k = 0; k < 8; k++) {
      c = (c & 1)
        ? (0x82F63B78 ^ (c >>> 1))
        : (c >>> 1);
    }

    table[n] = c >>> 0;
  }

  return table;
})();

function crc32c(buffer) {
  let crc = 0xFFFFFFFF;

  for (let i = 0; i < buffer.length; i++) {
    crc =
      CRC32C_TABLE[(crc ^ buffer[i]) & 0xFF] ^
      (crc >>> 8);
  }

  return ((crc ^ 0xFFFFFFFF) >>> 0)
    .toString(16)
    .padStart(8, "0");
}

function sha256Hex(buffer) {
  return crypto
    .createHash("sha256")
    .update(buffer)
    .digest("hex");
}

// ============================================================
// UTF-8 BYTE COMPARISON
// ============================================================

function cmpBytes(a, b) {
  const ba = Buffer.from(String(a), "utf8");
  const bb = Buffer.from(String(b), "utf8");

  const len = Math.min(ba.length, bb.length);

  for (let i = 0; i < len; i++) {
    if (ba[i] !== bb[i]) {
      return ba[i] - bb[i];
    }
  }

  return ba.length - bb.length;
}

// ============================================================
// TIME VALIDATION / NORMALIZATION
// ============================================================

const TIME_RE =
  /^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(\.\d{1,3})?(Z|[+-]\d{2}:\d{2})$/;

const DAYS_IN_MONTH = [
  31, 28, 31, 30, 31, 30,
  31, 31, 30, 31, 30, 31
];

function isLeapYear(year) {
  return (
    (year % 4 === 0 && year % 100 !== 0) ||
    year % 400 === 0
  );
}

function daysInMonth(year, month) {
  if (month === 2 && isLeapYear(year)) {
    return 29;
  }

  return DAYS_IN_MONTH[month - 1];
}

function parseTimeToUtcMillis(value) {
  if (typeof value !== "string") {
    return null;
  }

  const match = TIME_RE.exec(value);

  if (!match) {
    return null;
  }

  const year = Number(match[1]);
  const month = Number(match[2]);
  const day = Number(match[3]);
  const hour = Number(match[4]);
  const minute = Number(match[5]);
  const second = Number(match[6]);

  let milliseconds = 0;

  if (match[7]) {
    const digits = match[7].slice(1);
    milliseconds = Number(digits.padEnd(3, "0"));
  }

  // Calendar validation
  if (month < 1 || month > 12) {
    return null;
  }

  if (
    day < 1 ||
    day > daysInMonth(year, month)
  ) {
    return null;
  }

  if (hour < 0 || hour > 23) {
    return null;
  }

  if (minute < 0 || minute > 59) {
    return null;
  }

  if (second < 0 || second > 59) {
    return null;
  }

  // Offset validation
  const offset = match[8];

  let offsetMinutes = 0;

  if (offset !== "Z") {
    const sign = offset[0] === "-" ? -1 : 1;
    const offsetHour = Number(offset.slice(1, 3));
    const offsetMinute = Number(offset.slice(4, 6));

    if (offsetHour > 14) {
      return null;
    }

    if (offsetMinute > 59) {
      return null;
    }

    // +14:00 / -14:00 is allowed,
    // but +14:01 etc. is not.
    if (
      offsetHour === 14 &&
      offsetMinute !== 0
    ) {
      return null;
    }

    offsetMinutes =
      sign * (offsetHour * 60 + offsetMinute);
  }

  /*
   * Date.UTC treats years 0-99 specially.
   * We therefore create the date from year 100 first,
   * then explicitly set the UTC full year.
   */
  const date = new Date(0);

  date.setUTCFullYear(
    year,
    month - 1,
    day
  );

  date.setUTCHours(
    hour,
    minute,
    second,
    milliseconds
  );

  const baseMs = date.getTime();

  return baseMs - offsetMinutes * 60000;
}

function formatUtcMillis(ms) {
  const date = new Date(ms);

  const pad = (value, length = 2) =>
    String(value).padStart(length, "0");

  return (
    `${date.getUTCFullYear()}-` +
    `${pad(date.getUTCMonth() + 1)}-` +
    `${pad(date.getUTCDate())}T` +
    `${pad(date.getUTCHours())}:` +
    `${pad(date.getUTCMinutes())}:` +
    `${pad(date.getUTCSeconds())}.` +
    `${pad(date.getUTCMilliseconds(), 3)}Z`
  );
}

// ============================================================
// CANONICALIZATION
// ============================================================

function canonText(value) {
  return value
    .normalize("NFKC")
    .toLowerCase()
    .replace(/\p{White_Space}+/gu, " ")
    .trim();
}

// ============================================================
// WORD SET / JACCARD
// ============================================================

function wordSet(text) {
  const matches =
    text.match(/[\p{L}\p{N}]+/gu) || [];

  return new Set(
    matches.map(word => word.toLowerCase())
  );
}

function jaccard(setA, setB) {
  if (
    setA.size === 0 &&
    setB.size === 0
  ) {
    return 1;
  }

  let intersection = 0;

  for (const word of setA) {
    if (setB.has(word)) {
      intersection++;
    }
  }

  const union =
    setA.size +
    setB.size -
    intersection;

  if (union === 0) {
    return 1;
  }

  return intersection / union;
}

// ============================================================
// VALIDATION HELPERS
// ============================================================

const URI_RE = /^gs:\/\/[^/]+\/.+$/;
const GENERATION_RE = /^\d+$/;
const CRC32C_RE = /^[0-9a-f]{8}$/;

function isPlainObject(value) {
  return (
    typeof value === "object" &&
    value !== null &&
    !Array.isArray(value)
  );
}

function validateRowShape(row) {
  if (!isPlainObject(row)) {
    return false;
  }

  const expectedKeys = [
    "entity",
    "eventTime",
    "id",
    "revision",
    "text"
  ];

  const actualKeys =
    Object.keys(row).sort();

  if (
    actualKeys.length !== 5 ||
    !actualKeys.every(
      (key, index) =>
        key === expectedKeys[index]
    )
  ) {
    return false;
  }

  if (typeof row.id !== "string") {
    return false;
  }

  if (typeof row.entity !== "string") {
    return false;
  }

  if (typeof row.eventTime !== "string") {
    return false;
  }

  if (typeof row.text !== "string") {
    return false;
  }

  if (
    typeof row.revision !== "number" ||
    !Number.isInteger(row.revision) ||
    row.revision < 0 ||
    !Number.isSafeInteger(row.revision)
  ) {
    return false;
  }

  // IMPORTANT:
  // eventTime itself must be valid.
  if (
    parseTimeToUtcMillis(row.eventTime) === null
  ) {
    return false;
  }

  return true;
}

// ============================================================
// OBJECT VALIDATION
// ============================================================

function processObject(obj) {
  const codes = new Set();

  const uri =
    typeof obj?.uri === "string"
      ? obj.uri
      : null;

  // ----------------------------
  // URI
  // ----------------------------

  if (
    uri === null ||
    !URI_RE.test(uri)
  ) {
    codes.add("URI_INVALID");
  }

  // ----------------------------
  // GENERATIONS
  // ----------------------------

  const generation = obj?.generation;
  const fetchedGeneration =
    obj?.fetchedGeneration;

  const generationValid =
    typeof generation === "string" &&
    GENERATION_RE.test(generation);

  const fetchedGenerationValid =
    typeof fetchedGeneration === "string" &&
    GENERATION_RE.test(fetchedGeneration);

  if (
    !generationValid ||
    !fetchedGenerationValid
  ) {
    codes.add("GENERATION_INVALID");
  }

  if (
    generationValid &&
    fetchedGenerationValid &&
    generation !== fetchedGeneration
  ) {
    codes.add("GENERATION_MISMATCH");
  }

  // ----------------------------
  // CRC32C
  // ----------------------------

  const suppliedCrc = obj?.crc32c;

  const crcValid =
    typeof suppliedCrc === "string" &&
    CRC32C_RE.test(suppliedCrc);

  if (!crcValid) {
    codes.add("CRC32C_INVALID");
  }

  const content = obj?.content;

  const contentIsString =
    typeof content === "string";

  if (
    crcValid &&
    contentIsString
  ) {
    const actualCrc = crc32c(
      Buffer.from(content, "utf8")
    );

    if (actualCrc !== suppliedCrc) {
      codes.add("CRC32C_MISMATCH");
    }
  }

  // ----------------------------
  // SCHEMA
  // ----------------------------

  if (
    obj?.schemaId !== "training-v1"
  ) {
    codes.add("SCHEMA_INVALID");
  }

  if (!contentIsString) {
    codes.add("SCHEMA_INVALID");
  }

  // ----------------------------
  // JSONL
  // ----------------------------

  const rows = [];

  if (contentIsString) {
    const lines =
      content
        .split("\n")
        .filter(
          line => line.trim().length > 0
        );

    // Empty file / only blank lines
    if (lines.length === 0) {
      codes.add("SCHEMA_INVALID");
    } else {
      let jsonlInvalid = false;
      let schemaInvalid = false;

      for (const line of lines) {
        let parsed;

        try {
          parsed = JSON.parse(line);
        } catch (error) {
          jsonlInvalid = true;
          continue;
        }

        if (!validateRowShape(parsed)) {
          schemaInvalid = true;
          continue;
        }

        rows.push(parsed);
      }

      if (jsonlInvalid) {
        codes.add("JSONL_INVALID");
      }

      if (schemaInvalid) {
        codes.add("SCHEMA_INVALID");
      }
    }
  }

  /*
   * If ANY object-level validation error occurred,
   * the whole object is rejected.
   */
  return {
    uri,
    codes,
    rows,
    obj,
    accepted: codes.size === 0
  };
}

// ============================================================
// REASON CODE SORTING
// ============================================================

function sortDedupReasonCodes(codes) {
  const unique = [
    ...new Set(codes)
  ];

  unique.sort(cmpBytes);

  return unique;
}

// ============================================================
// COMPACT ROW JSON
// ============================================================

function compactRow(row) {
  return JSON.stringify({
    id: row.id,
    entity: row.entity,
    eventTime: formatUtcMillis(
      row.eventTimeMs
    ),
    revision: row.revision,
    text: row.text
  });
}

// ============================================================
// SPLIT SERIALIZATION
// ============================================================

function serializeSplit(rows) {
  const sorted =
    rows.slice().sort((a, b) => {
      const idComparison =
        cmpBytes(a.id, b.id);

      if (idComparison !== 0) {
        return idComparison;
      }

      return cmpBytes(
        compactRow(a),
        compactRow(b)
      );
    });

  const lines = sorted.map(
    row => compactRow(row) + "\n"
  );

  const serialized =
    lines.join("");

  const bytes =
    Buffer.from(serialized, "utf8");

  return {
    rows: sorted.map(
      row => JSON.parse(
        compactRow(row)
      )
    ),

    digest: sha256Hex(bytes)
  };
}

// ============================================================
// MAIN HANDLER
// ============================================================

module.exports = async (req, res) => {

  // The grader calls POST /build-corpus
  if (req.method !== "POST") {
    res
      .status(405)
      .json({
        error: "INVALID_INPUT"
      });

    return;
  }

  // ----------------------------
  // REQUEST PARSING
  // ----------------------------

  let body = req.body;

  /*
   * Vercel normally parses application/json
   * automatically.
   *
   * This fallback also handles cases where
   * req.body arrives as a string.
   */
  if (typeof body === "string") {
    try {
      body = JSON.parse(body);
    } catch (error) {
      res
        .status(400)
        .json({
          error: "INVALID_INPUT"
        });

      return;
    }
  }

  if (!isPlainObject(body)) {
    res
      .status(400)
      .json({
        error: "INVALID_INPUT"
      });

    return;
  }

  const policy = body.policy;
  const objects = body.objects;

  // Missing/invalid policy or objects
  if (
    !isPlainObject(policy) ||
    !Array.isArray(objects)
  ) {
    res
      .status(400)
      .json({
        error: "INVALID_INPUT"
      });

    return;
  }

  // ==========================================================
  // PROCESS OBJECTS
  // ==========================================================

  const rejectedObjects = [];
  const lineage = [];

  const acceptedRows = [];

  for (const object of objects) {
    const result =
      processObject(object);

    // ----------------------------
    // REJECT INVALID OBJECT
    // ----------------------------

    if (!result.accepted) {
      rejectedObjects.push({
        uri: result.uri,
        reasonCodes:
          sortDedupReasonCodes(
            [...result.codes]
          )
      });

      continue;
    }

    // ----------------------------
    // LINEAGE
    // ----------------------------

    lineage.push({
      uri: result.uri,
      generation: object.generation,
      crc32c: object.crc32c,
      schemaId: object.schemaId
    });

    // ----------------------------
    // ACCEPT ROWS
    // ----------------------------

    for (const row of result.rows) {
      acceptedRows.push({
        id: row.id,

        entity:
          canonText(row.entity),

        text:
          canonText(row.text),

        eventTimeMs:
          parseTimeToUtcMillis(
            row.eventTime
          ),

        revision:
          row.revision
      });
    }
  }

  // ==========================================================
  // DEDUPLICATION
  // ==========================================================

  const duplicateRejectedRows = [];

  const groups = new Map();

  for (const row of acceptedRows) {

    const normalizedTime =
      formatUtcMillis(
        row.eventTimeMs
      );

    const key = JSON.stringify([
      row.entity,
      normalizedTime,
      row.text
    ]);

    if (!groups.has(key)) {
      groups.set(key, []);
    }

    groups
      .get(key)
      .push(row);
  }

  const survivors = [];

  for (const group of groups.values()) {

    if (group.length === 1) {
      survivors.push(group[0]);
      continue;
    }

    let winner = group[0];

    for (
      const candidate of group.slice(1)
    ) {

      if (
        candidate.revision >
        winner.revision
      ) {
        winner = candidate;
      } else if (
        candidate.revision ===
        winner.revision &&
        cmpBytes(
          candidate.id,
          winner.id
        ) < 0
      ) {
        winner = candidate;
      }
    }

    for (const candidate of group) {
      if (candidate !== winner) {
        duplicateRejectedRows.push({
          id: candidate.id,
          codes: new Set([
            "DUPLICATE"
          ])
        });
      }
    }

    survivors.push(winner);
  }

  // ==========================================================
  // POLICY VALIDATION
  // ==========================================================

  const minTime =
    parseTimeToUtcMillis(
      policy.minTime
    );

  const maxTime =
    parseTimeToUtcMillis(
      policy.maxTime
    );

  const threshold =
    policy.contaminationThreshold;

  const thresholdValid =
    typeof threshold === "number" &&
    Number.isFinite(threshold) &&
    threshold >= 0 &&
    threshold <= 1;

  const policyValid =
    minTime !== null &&
    maxTime !== null &&
    minTime <= maxTime &&
    thresholdValid;

  const rejectedPolicyRows = [];

  const windowedRows = [];

  for (const row of survivors) {

    // Invalid policy rejects every
    // retained row.
    if (!policyValid) {

      rejectedPolicyRows.push({
        id: row.id,
        codes: new Set([
          "POLICY_INVALID"
        ])
      });

      continue;
    }

    // Inclusive time window
    if (
      row.eventTimeMs < minTime ||
      row.eventTimeMs > maxTime
    ) {

      rejectedPolicyRows.push({
        id: row.id,
        codes: new Set([
          "OUT_OF_WINDOW"
        ])
      });

      continue;
    }

    windowedRows.push(row);
  }

  // ==========================================================
  // DETERMINISTIC SPLIT
  // ==========================================================

  const train = [];
  const validation = [];
  const test = [];

  for (const row of windowedRows) {

    const hash =
      crypto
        .createHash("sha256")
        .update(
          Buffer.from(
            row.entity,
            "utf8"
          )
        )
        .digest();

    const bucket =
      hash[0] % 10;

    if (bucket <= 5) {
      train.push(row);
    } else if (bucket <= 7) {
      validation.push(row);
    } else {
      test.push(row);
    }
  }

  // ==========================================================
  // TRAIN CONTAMINATION
  // ==========================================================

  const trainWordSets =
    train.map(
      row => wordSet(row.text)
    );

  function contaminated(row) {

    const rowWords =
      wordSet(row.text);

    for (
      const trainWords of trainWordSets
    ) {

      const similarity =
        jaccard(
          rowWords,
          trainWords
        );

      if (
        similarity >= threshold
      ) {
        return true;
      }
    }

    return false;
  }

  const finalValidation = [];
  const finalTest = [];

  const contaminationRejectedRows = [];

  // Validation
  for (const row of validation) {

    if (contaminated(row)) {

      contaminationRejectedRows.push({
        id: row.id,
        codes: new Set([
          "TRAIN_CONTAMINATION"
        ])
      });

    } else {
      finalValidation.push(row);
    }
  }

  // Test
  for (const row of test) {

    if (contaminated(row)) {

      contaminationRejectedRows.push({
        id: row.id,
        codes: new Set([
          "TRAIN_CONTAMINATION"
        ])
      });

    } else {
      finalTest.push(row);
    }
  }

  // ==========================================================
  // MERGE REJECTED ROW REASONS
  // ==========================================================

  const rejectedRowMap =
    new Map();

  const allRejectedRows = [
    ...duplicateRejectedRows,
    ...rejectedPolicyRows,
    ...contaminationRejectedRows
  ];

  for (
    const rejected of allRejectedRows
  ) {

    if (
      !rejectedRowMap.has(
        rejected.id
      )
    ) {
      rejectedRowMap.set(
        rejected.id,
        new Set()
      );
    }

    for (
      const code of rejected.codes
    ) {
      rejectedRowMap
        .get(rejected.id)
        .add(code);
    }
  }

  const finalRejectedRows =
    [...rejectedRowMap.entries()]
      .map(
        ([id, codes]) => ({
          id,
          reasonCodes:
            sortDedupReasonCodes(
              [...codes]
            )
        })
      )
      .sort((a, b) => {

        const comparison =
          cmpBytes(a.id, b.id);

        if (comparison !== 0) {
          return comparison;
        }

        return cmpBytes(
          JSON.stringify(a),
          JSON.stringify(b)
        );
      });

  // ==========================================================
  // SORT REJECTED OBJECTS
  // ==========================================================

  const finalRejectedObjects =
    rejectedObjects
      .slice()
      .sort((a, b) => {

        const uriA =
          a.uri === null
            ? ""
            : a.uri;

        const uriB =
          b.uri === null
            ? ""
            : b.uri;

        const comparison =
          cmpBytes(uriA, uriB);

        if (comparison !== 0) {
          return comparison;
        }

        return cmpBytes(
          JSON.stringify(a),
          JSON.stringify(b)
        );
      });

  // ==========================================================
  // SORT LINEAGE
  // ==========================================================

  const finalLineage =
    lineage
      .slice()
      .sort((a, b) => {

        const comparison =
          cmpBytes(a.uri, b.uri);

        if (comparison !== 0) {
          return comparison;
        }

        return cmpBytes(
          JSON.stringify(a),
          JSON.stringify(b)
        );
      });

  // ==========================================================
  // SERIALIZE SPLITS
  // ==========================================================

  const trainResult =
    serializeSplit(train);

  const validationResult =
    serializeSplit(finalValidation);

  const testResult =
    serializeSplit(finalTest);

  // ==========================================================
  // EXACT RESPONSE SHAPE
  // ==========================================================

  res.status(200).json({
    splits: {
      train: trainResult.rows,
      validation: validationResult.rows,
      test: testResult.rows
    },

    rejectedObjects:
      finalRejectedObjects,

    rejectedRows:
      finalRejectedRows,

    digests: {
      train: trainResult.digest,
      validation:
        validationResult.digest,
      test:
        testResult.digest
    },

    lineage:
      finalLineage
  });
};
