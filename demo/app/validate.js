// Input helpers for the demo app.

/** Keep only digits, so an id can be put into a query safely. */
function sanitizeId(raw) {
  return String(raw).replace(/[^0-9]/g, "");
}

module.exports = { sanitizeId };
