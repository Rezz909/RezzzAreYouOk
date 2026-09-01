import express from "express";
import crypto from "crypto";
import pg from "pg";

const { Pool } = pg;

const app = express();
const PORT = process.env.PORT || 3000;

const LEASE_MS = 90_000;
const MAX_ATTEMPTS = 5;
const DONE_RETENTION_MS = 60 * 60 * 1000;

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.NODE_ENV === "production"
    ? { rejectUnauthorized: false }
    : false,
});

app.use(express.json({
  verify: (req, res, buf) => {
    req.rawBody = buf.toString("utf8");
  }
}));

function json(res, data, status = 200) {
  return res.status(status).json(data);
}

async function verifySaweriaSignature(rawBody, signatureHeader, streamKey) {
  if (!streamKey) return true;
  if (!signatureHeader) return false;

  const hmac = crypto.createHmac("sha256", streamKey);
  hmac.update(rawBody);
  const hex = hmac.digest("hex");

  if (hex.length !== signatureHeader.length) return false;

  let diff = 0;
  for (let i = 0; i < hex.length; i++) {
    diff |= hex.charCodeAt(i) ^ signatureHeader.charCodeAt(i);
  }

  return diff === 0;
}

async function initDb() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS donations (
      id TEXT PRIMARY KEY,
      amount_raw BIGINT,
      donator_name TEXT,
      message TEXT,
      created_at TEXT,
      status TEXT NOT NULL DEFAULT 'pending',
      lease_token TEXT,
      lease_expires BIGINT NOT NULL DEFAULT 0,
      attempts INTEGER NOT NULL DEFAULT 0,
      last_error TEXT NOT NULL DEFAULT '',
      done_at BIGINT
    )
  `);

  console.log("Database ready");
}

async function pushItem(payload) {
  const exists = await pool.query(
    "SELECT id FROM donations WHERE id = $1 LIMIT 1",
    [payload.id]
  );

  if (exists.rows.length > 0) {
    return { ok: true, deduped: true };
  }

  await pool.query(`
    INSERT INTO donations (
      id,
      amount_raw,
      donator_name,
      message,
      created_at,
      status,
      lease_token,
      lease_expires,
      attempts,
      last_error
    )
    VALUES ($1, $2, $3, $4, $5, 'pending', NULL, 0, 0, '')
  `, [
    payload.id,
    payload.amount_raw ?? 0,
    payload.donator_name ?? "",
    payload.message ?? "",
    payload.created_at ?? new Date().toISOString()
  ]);

  return { ok: true };
}

async function pullItems(limit) {
  const client = await pool.connect();

  try {
    await client.query("BEGIN");

    const now = Date.now();

    await client.query(`
      UPDATE donations
      SET
        status = 'pending',
        lease_token = NULL,
        lease_expires = 0
      WHERE status = 'leased'
      AND lease_expires < $1
    `, [now]);

    const rows = await client.query(`
      SELECT *
      FROM donations
      WHERE status = 'pending'
      ORDER BY created_at ASC
      LIMIT $1
      FOR UPDATE SKIP LOCKED
    `, [limit]);

    const output = [];

    for (const item of rows.rows) {
      const leaseToken = crypto.randomUUID();
      const leaseExpires = now + LEASE_MS;

      await client.query(`
        UPDATE donations
        SET
          status = 'leased',
          lease_token = $1,
          lease_expires = $2,
          attempts = attempts + 1
        WHERE id = $3
      `, [
        leaseToken,
        leaseExpires,
        item.id
      ]);

      output.push({
        id: item.id,
        leaseToken,
        amount: item.amount_raw,
        amount_raw: item.amount_raw,
        donator_name: item.donator_name,
        message: item.message,
        createdAt: item.created_at,
        created_at: item.created_at
      });
    }

    await client.query("COMMIT");

    return output;
  } catch (err) {
    await client.query("ROLLBACK");
    throw err;
  } finally {
    client.release();
  }
}

async function ackItems(acks) {
  const client = await pool.connect();

  try {
    await client.query("BEGIN");

    for (const ack of acks) {
      const result = await client.query(
        "SELECT * FROM donations WHERE id = $1 LIMIT 1",
        [ack.id]
      );

      if (result.rows.length === 0) continue;

      const item = result.rows[0];

      if (
        item.lease_token &&
        ack.leaseToken &&
        item.lease_token !== ack.leaseToken
      ) {
        continue;
      }

      if (ack.status === "done") {
        await client.query(`
          UPDATE donations
          SET
            status = 'done',
            done_at = $1
          WHERE id = $2
        `, [
          Date.now(),
          ack.id
        ]);
      } else {
        const nextStatus =
          item.attempts >= MAX_ATTEMPTS
            ? "dead"
            : "pending";

        await client.query(`
          UPDATE donations
          SET
            status = $1,
            lease_token = NULL,
            lease_expires = 0,
            last_error = $2
          WHERE id = $3
        `, [
          nextStatus,
          String(ack.error || "").slice(0, 250),
          ack.id
        ]);
      }
    }

    const cutoff = Date.now() - DONE_RETENTION_MS;

    await client.query(`
      DELETE FROM donations
      WHERE status = 'done'
      AND done_at < $1
    `, [cutoff]);

    await client.query("COMMIT");
  } catch (err) {
    await client.query("ROLLBACK");
    throw err;
  } finally {
    client.release();
  }
}

app.get("/", (req, res) => {
  return json(res, {
    ok: true,
    service: "Rezzz Backend",
    message: "Backend online"
  });
});

app.get("/health", async (req, res) => {
  try {
    await pool.query("SELECT 1");

    return json(res, {
      ok: true,
      service: "rezzz-backend",
      database: "connected"
    });
  } catch (err) {
    return json(res, {
      ok: false,
      database: "disconnected",
      error: err.message
    }, 500);
  }
});

app.post("/webhook", async (req, res) => {
  try {
    const rawBody = req.rawBody || JSON.stringify(req.body || {});

    const signature =
      req.headers["saweria-callback-signature"] || "";

    const valid = await verifySaweriaSignature(
      rawBody,
      signature,
      process.env.SAWERIA_STREAM_KEY
    );

    if (!valid) {
      return json(res, {
        ok: false,
        error: "invalid_signature"
      }, 401);
    }

    const payload = req.body || {};

    if (payload.type && payload.type !== "donation") {
      return json(res, {
        ok: true,
        skipped: true
      });
    }

    const result = await pushItem({
      id: payload.id || crypto.randomUUID(),
      amount_raw: payload.amount_raw,
      donator_name: payload.donator_name,
      message: payload.message,
      created_at: payload.created_at
    });

    return json(res, result);
  } catch (err) {
    console.error(err);

    return json(res, {
      ok: false,
      error: err.message
    }, 500);
  }
});

app.post("/api/pull", async (req, res) => {
  try {
    const limit = Math.max(
      1,
      Math.min(
        25,
        Number(req.body?.limit) || 10
      )
    );

    const items = await pullItems(limit);

    return json(res, {
      ok: true,
      items
    });
  } catch (err) {
    console.error(err);

    return json(res, {
      ok: false,
      error: err.message
    }, 500);
  }
});

app.post("/api/ack", async (req, res) => {
  try {
    const acks = Array.isArray(req.body?.items)
      ? req.body.items
      : [];

    await ackItems(acks);

    return json(res, {
      ok: true
    });
  } catch (err) {
    console.error(err);

    return json(res, {
      ok: false,
      error: err.message
    }, 500);
  }
});

app.post("/debug/push", async (req, res) => {
  try {
    if (
      !process.env.DEBUG_TOKEN ||
      req.headers["x-debug-token"] !== process.env.DEBUG_TOKEN
    ) {
      return json(res, {
        ok: false,
        error: "unauthorized"
      }, 401);
    }

    const payload = req.body || {};

    const result = await pushItem({
      id: payload.id || crypto.randomUUID(),
      amount_raw: payload.amount_raw || 5000,
      donator_name: payload.donator_name || "Tester",
      message: payload.message || "test donasi",
      created_at: new Date().toISOString()
    });

    return json(res, result);
  } catch (err) {
    return json(res, {
      ok: false,
      error: err.message
    }, 500);
  }
});

app.get("/debug/queue", async (req, res) => {
  try {
    if (
      !process.env.DEBUG_TOKEN ||
      req.headers["x-debug-token"] !== process.env.DEBUG_TOKEN
    ) {
      return json(res, {
        ok: false,
        error: "unauthorized"
      }, 401);
    }

    const result = await pool.query(`
      SELECT *
      FROM donations
      ORDER BY created_at ASC
    `);

    return json(res, {
      ok: true,
      count: result.rows.length,
      items: result.rows
    });
  } catch (err) {
    return json(res, {
      ok: false,
      error: err.message
    }, 500);
  }
});

app.post("/admin/retry", async (req, res) => {
  try {
    if (
      !process.env.DEBUG_TOKEN ||
      req.headers["x-debug-token"] !== process.env.DEBUG_TOKEN
    ) {
      return json(res, {
        ok: false,
        error: "unauthorized"
      }, 401);
    }

    const id = req.body?.id;

    const result = await pool.query(`
      UPDATE donations
      SET
        status = 'pending',
        lease_token = NULL,
        lease_expires = 0,
        attempts = 0,
        last_error = ''
      WHERE id = $1
      RETURNING id
    `, [id]);

    if (result.rows.length === 0) {
      return json(res, {
        ok: false,
        error: "not_found"
      }, 404);
    }

    return json(res, {
      ok: true
    });
  } catch (err) {
    return json(res, {
      ok: false,
      error: err.message
    }, 500);
  }
});

app.post("/admin/delete", async (req, res) => {
  try {
    if (
      !process.env.DEBUG_TOKEN ||
      req.headers["x-debug-token"] !== process.env.DEBUG_TOKEN
    ) {
      return json(res, {
        ok: false,
        error: "unauthorized"
      }, 401);
    }

    const id = req.body?.id;

    const result = await pool.query(
      "DELETE FROM donations WHERE id = $1",
      [id]
    );

    return json(res, {
      ok: true,
      removed: result.rowCount > 0
    });
  } catch (err) {
    return json(res, {
      ok: false,
      error: err.message
    }, 500);
  }
});

initDb()
  .then(() => {
    app.listen(PORT, "0.0.0.0", () => {
      console.log(`Rezzz Backend running on port ${PORT}`);
    });
  })
  .catch((err) => {
    console.error("Database init failed:", err);
    process.exit(1);
  });
