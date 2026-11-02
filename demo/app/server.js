const express = require("express");
const { Pool } = require("pg");
const _ = require("lodash");

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

app.listen(process.env.PORT ?? 3000);
