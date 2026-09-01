import express from "express";
import crypto from "crypto";
import pg from "pg";

const { Pool } = pg;

const app = express();
const PORT = process.env.PORT || 3000;

const LEASE_MS = 90_000;
const MAX_ATTEMPTS = 5;
const DONE_RETENTION_MS = 60 * 60 * 1000;

if (!process.env.DATABASE_URL) {
  console.error("DATABASE_URL belum ada");
  process.exit(1);
}

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
});

app.use(
  express.json({
    verify: (req, res, buf) => {
      req.rawBody = buf.toString("utf8");
    },
  })
);

function sendJson(res, data, status = 200) {
  return res.status(status).json(data);
}

async function verifySaweriaSignature(rawBody, signatureHeader, streamKey) {
  if (!streamKey) return true;
  if (!signatureHeader) return false;

  const expected = crypto
    .createHmac("sha256", streamKey)
    .update(rawBody)
    .digest("hex");

  if (expected.length !== signatureHeader.length) return false;

  try {
    return crypto.timingSafeEqual(
      Buffer.from(expected),
      Buffer.from(signatureHeader)
    );
  } catch {
    return false;
  }
}

async function initDatabase() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS donations (
      id TEXT PRIMARY KEY,
      amount_raw BIGINT DEFAULT 0,
      donator_name TEXT DEFAULT '',
      message TEXT DEFAULT '',
      created_at TEXT,
      status TEXT NOT NULL DEFAULT 'pending',
      lease_token TEXT,
      lease_expires BIGINT NOT NULL DEFAULT 0,
      attempts INTEGER NOT NULL DEFAULT 0,
      last_error TEXT NOT NULL DEFAULT '',
      done_at BIGINT
    )
  `);

  console.log("Database connected");
}

async function pushItem(payload) {
  const id = payload.id || crypto.randomUUID();

  const result = await pool.query(
    `
    INSERT INTO donations (
      id,
      amount_raw,
      donator_name,
      message,
      created_at
    )
    VALUES ($1, $2, $3, $4, $5)
    ON CONFLICT (id) DO NOTHING
    RETURNING id
    `,
    [
      id,
      Number(payload.amount_raw || 0),
      payload.donator_name || "",
      payload.message || "",
      payload.created_at || new Date().toISOString(),
    ]
  );

  if (result.rowCount === 0) {
    return {
      ok: true,
      deduped: true,
    };
  }

  return {
    ok: true,
    id,
  };
}

async function pullItems(limit) {
  const client = await pool.connect();

  try {
    await client.query("BEGIN");

    const now = Date.now();

    await client.query(
      `
      UPDATE donations
      SET
        status = 'pending',
        lease_token = NULL,
        lease_expires = 0
      WHERE status = 'leased'
      AND lease_expires < $1
      `,
      [now]
    );

    const result = await client.query(
      `
      SELECT *
      FROM donations
      WHERE status = 'pending'
      ORDER BY created_at ASC
      LIMIT $1
      FOR UPDATE SKIP LOCKED
      `,
      [limit]
    );

    const output = [];

    for (const item of result.rows) {
      const leaseToken = crypto.randomUUID();
      const leaseExpires = now + LEASE_MS;

      await client.query(
        `
        UPDATE donations
        SET
          status = 'leased',
          lease_token = $1,
          lease_expires = $2,
          attempts = attempts + 1
        WHERE id = $3
        `,
        [leaseToken, leaseExpires, item.id]
      );

      output.push({
        id: item.id,
        leaseToken,
        amount: Number(item.amount_raw),
        amount_raw: Number(item.amount_raw),
        donator_name: item.donator_name,
        message: item.message,
        createdAt: item.created_at,
        created_at: item.created_at,
      });
    }

    await client.query("COMMIT");

    return output;
  } catch (error) {
    await client.query("ROLLBACK");
    throw error;
  } finally {
    client.release();
  }
}

async function ackItems(acks) {
  const client = await pool.connect();

  try {
    await client.query("BEGIN");

    for (const ack of acks) {
      if (!ack?.id) continue;

      const result = await client.query(
        `
        SELECT *
        FROM donations
        WHERE id = $1
        LIMIT 1
        `,
        [ack.id]
      );

      if (result.rowCount === 0) continue;

      const item = result.rows[0];

      if (
        item.lease_token &&
        ack.leaseToken &&
        item.lease_token !== ack.leaseToken
      ) {
        continue;
      }

      if (ack.status === "done") {
        await client.query(
          `
          UPDATE donations
          SET
            status = 'done',
            done_at = $1,
            lease_token = NULL,
            lease_expires = 0
          WHERE id = $2
          `,
          [Date.now(), ack.id]
        );
      } else {
        const status =
          Number(item.attempts) >= MAX_ATTEMPTS ? "dead" : "pending";

        await client.query(
          `
          UPDATE donations
          SET
            status = $1,
            lease_token = NULL,
            lease_expires = 0,
            last_error = $2
          WHERE id = $3
          `,
          [
            status,
            String(ack.error || "").slice(0, 250),
            ack.id,
          ]
        );
      }
    }

    const cutoff = Date.now() - DONE_RETENTION_MS;

    await client.query(
      `
      DELETE FROM donations
      WHERE status = 'done'
      AND done_at < $1
      `,
      [cutoff]
    );

    await client.query("COMMIT");
  } catch (error) {
    await client.query("ROLLBACK");
    throw error;
  } finally {
    client.release();
  }
}

app.get("/", (req, res) => {
  return sendJson(res, {
    ok: true,
    service: "Rezzz Backend",
  });
});

app.get("/health", async (req, res) => {
  try {
    await pool.query("SELECT 1");

    return sendJson(res, {
      ok: true,
      service: "rezzz-backend",
      database: "connected",
    });
  } catch (error) {
    return sendJson(
      res,
      {
        ok: false,
        database: "disconnected",
        error: error.message,
      },
      500
    );
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
      return sendJson(
        res,
        {
          ok: false,
          error: "invalid_signature",
        },
        401
      );
    }

    const payload = req.body || {};

    if (payload.type && payload.type !== "donation") {
      return sendJson(res, {
        ok: true,
        skipped: true,
      });
    }

    const result = await pushItem({
      id: payload.id,
      amount_raw: payload.amount_raw,
      donator_name: payload.donator_name,
      message: payload.message,
      created_at: payload.created_at,
    });

    return sendJson(res, result);
  } catch (error) {
    console.error(error);

    return sendJson(
      res,
      {
        ok: false,
        error: error.message,
      },
      500
    );
  }
});

app.post("/api/pull", async (req, res) => {
  try {
    const limit = Math.max(
      1,
      Math.min(25, Number(req.body?.limit) || 10)
    );

    const items = await pullItems(limit);

    return sendJson(res, {
      ok: true,
      items,
    });
  } catch (error) {
    console.error(error);

    return sendJson(
      res,
      {
        ok: false,
        error: error.message,
      },
      500
    );
  }
});

app.post("/api/ack", async (req, res) => {
  try {
    const items = Array.isArray(req.body?.items)
      ? req.body.items
      : [];

    await ackItems(items);

    return sendJson(res, {
      ok: true,
    });
  } catch (error) {
    console.error(error);

    return sendJson(
      res,
      {
        ok: false,
        error: error.message,
      },
      500
    );
  }
});

app.post("/debug/push", async (req, res) => {
  try {
    if (
      !process.env.DEBUG_TOKEN ||
      req.headers["x-debug-token"] !== process.env.DEBUG_TOKEN
    ) {
      return sendJson(
        res,
        {
          ok: false,
          error: "unauthorized",
        },
        401
      );
    }

    const result = await pushItem({
      id: req.body?.id,
      amount_raw: req.body?.amount_raw || 5000,
      donator_name: req.body?.donator_name || "Tester",
      message: req.body?.message || "test donasi",
      created_at: new Date().toISOString(),
    });

    return sendJson(res, result);
  } catch (error) {
    return sendJson(
      res,
      {
        ok: false,
        error: error.message,
      },
      500
    );
  }
});

app.get("/debug/queue", async (req, res) => {
  try {
    if (
      !process.env.DEBUG_TOKEN ||
      req.headers["x-debug-token"] !== process.env.DEBUG_TOKEN
    ) {
      return sendJson(
        res,
        {
          ok: false,
          error: "unauthorized",
        },
        401
      );
    }

    const result = await pool.query(`
      SELECT *
      FROM donations
      ORDER BY created_at ASC
    `);

    return sendJson(res, {
      ok: true,
      count: result.rowCount,
      items: result.rows,
    });
  } catch (error) {
    return sendJson(
      res,
      {
        ok: false,
        error: error.message,
      },
      500
    );
  }
});

app.post("/admin/retry", async (req, res) => {
  try {
    if (
      !process.env.DEBUG_TOKEN ||
      req.headers["x-debug-token"] !== process.env.DEBUG_TOKEN
    ) {
      return sendJson(
        res,
        {
          ok: false,
          error: "unauthorized",
        },
        401
      );
    }

    const result = await pool.query(
      `
      UPDATE donations
      SET
        status = 'pending',
        lease_token = NULL,
        lease_expires = 0,
        attempts = 0,
        last_error = ''
      WHERE id = $1
      RETURNING id
      `,
      [req.body?.id]
    );

    if (result.rowCount === 0) {
      return sendJson(
        res,
        {
          ok: false,
          error: "not_found",
        },
        404
      );
    }

    return sendJson(res, {
      ok: true,
    });
  } catch (error) {
    return sendJson(
      res,
      {
        ok: false,
        error: error.message,
      },
      500
    );
  }
});

app.post("/admin/delete", async (req, res) => {
  try {
    if (
      !process.env.DEBUG_TOKEN ||
      req.headers["x-debug-token"] !== process.env.DEBUG_TOKEN
    ) {
      return sendJson(
        res,
        {
          ok: false,
          error: "unauthorized",
        },
        401
      );
    }

    const result = await pool.query(
      `
      DELETE FROM donations
      WHERE id = $1
      `,
      [req.body?.id]
    );

    return sendJson(res, {
      ok: true,
      removed: result.rowCount > 0,
    });
  } catch (error) {
    return sendJson(
      res,
      {
        ok: false,
        error: error.message,
      },
      500
    );
  }
});

async function start() {
  try {
    await initDatabase();

    app.listen(PORT, "0.0.0.0", () => {
      console.log(`Server running on port ${PORT}`);
    });
  } catch (error) {
    console.error("START ERROR:", error);
    process.exit(1);
  }
}

start();
