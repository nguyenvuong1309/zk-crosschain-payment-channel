// Minimal HTTP API for parties (or their wallet/client) to checkpoint a
// freshly co-signed ChannelState with this watchtower. No framework
// dependency — Node's built-in `http` is enough for what this needs.
//
//   POST /checkpoint
//     body: { channelId, nonce, balanceA, balanceB, sigA, sigB }
//     -> 200 { stored: true } | 200 { stored: false, reason } | 400 { error }
//
//   GET /checkpoint/:channelId
//     -> 200 <stored checkpoint> | 404
//
//   GET /health -> 200 "ok"

const http = require("http");
const { submitCheckpoint, InvalidCheckpointError } = require("./checkpoint");

function readBody(req) {
  return new Promise((resolve, reject) => {
    let data = "";
    req.on("data", (chunk) => (data += chunk));
    req.on("end", () => resolve(data));
    req.on("error", reject);
  });
}

function createServer({ paymentChannel, store }) {
  return http.createServer(async (req, res) => {
    try {
      if (req.method === "GET" && req.url === "/health") {
        res.writeHead(200, { "Content-Type": "text/plain" });
        res.end("ok");
        return;
      }

      if (req.method === "GET" && req.url.startsWith("/checkpoint/")) {
        const channelId = req.url.split("/")[2];
        const paymentChannelAddress = await paymentChannel.getAddress();
        const checkpoint = store.getLatest(paymentChannelAddress, channelId);
        if (!checkpoint) {
          res.writeHead(404, { "Content-Type": "application/json" });
          res.end(JSON.stringify({ error: "no checkpoint on file" }));
          return;
        }
        res.writeHead(200, { "Content-Type": "application/json" });
        res.end(JSON.stringify(checkpoint));
        return;
      }

      if (req.method === "POST" && req.url === "/checkpoint") {
        const body = JSON.parse(await readBody(req));
        const { channelId, nonce, balanceA, balanceB, sigA, sigB } = body;
        if ([channelId, nonce, balanceA, balanceB, sigA, sigB].some((v) => v === undefined)) {
          res.writeHead(400, { "Content-Type": "application/json" });
          res.end(JSON.stringify({ error: "missing field(s) — need channelId, nonce, balanceA, balanceB, sigA, sigB" }));
          return;
        }

        const result = await submitCheckpoint({ paymentChannel, store, state: { channelId, nonce, balanceA, balanceB } }, sigA, sigB);
        res.writeHead(200, { "Content-Type": "application/json" });
        res.end(JSON.stringify(result));
        return;
      }

      res.writeHead(404, { "Content-Type": "application/json" });
      res.end(JSON.stringify({ error: "not found" }));
    } catch (err) {
      const status = err instanceof InvalidCheckpointError ? 400 : 500;
      res.writeHead(status, { "Content-Type": "application/json" });
      res.end(JSON.stringify({ error: err.message }));
    }
  });
}

module.exports = { createServer };
