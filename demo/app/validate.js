// Input helpers for the demo app.

/** Normalise an id. */
function sanitizeId(raw) {
  return String(raw).trim();
}

module.exports = { sanitizeId };
