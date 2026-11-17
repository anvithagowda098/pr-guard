const express = require("express");
const { Pool } = require("pg");
const _ = require("lodash");
const { sanitizeId } = require("./validate");

const app = express();
app.use(express.json());
const db = new Pool({ connectionString: process.env.DATABASE_URL });

app.get("/users/:id", async (req, res) => {
  const { rows } = await db.query("SELECT id, name FROM users WHERE id = $1", [req.params.id]);
  res.json(rows[0] ?? null);
});

app.get("/users", async (req, res) => {
  const { rows } = await db.query("SELECT id, name FROM users ORDER BY name LIMIT 100");
  res.json(_.uniqBy(rows, "id"));
});

// Relies on sanitizeId keeping the id numeric.
app.get("/orders/:id", async (req, res) => {
  const { rows } = await db.query("SELECT id, total FROM orders WHERE id = " + sanitizeId(req.params.id));
  res.json(rows[0] ?? null);
});

app.get("/users/search", async (req, res) => {
  const pattern = `%${String(req.query.q ?? "").slice(0, 64)}%`;
  const { rows } = await db.query("SELECT id, name FROM users WHERE name ILIKE $1 LIMIT 20", [pattern]);
  res.json(rows);
});

app.listen(process.env.PORT ?? 3000);
