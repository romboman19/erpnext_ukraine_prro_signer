"use strict";

const express = require("express");
const { sign, unwrap, SignerError } = require("./signer");

const PORT = Number(process.env.PORT || 8080);
const API_KEY = process.env.API_KEY;

if (!API_KEY) {
	console.error("[prro-signer] API_KEY env variable is required");
	process.exit(1);
}

const app = express();
app.disable("x-powered-by");
app.use(express.json({ limit: "10mb" }));

app.get("/health", (_req, res) => {
	res.json({ status: "ok", service: "prro-signer", uptime: process.uptime() });
});

app.use((req, res, next) => {
	if (req.get("x-api-key") !== API_KEY) {
		return res.status(401).json({ error: "unauthorized" });
	}
	next();
});

function b64(field, value) {
	try {
		const buf = Buffer.from(value, "base64");
		if (!buf.length) throw new Error();
		return buf;
	} catch {
		throw new SignerError(`Поле ${field} має бути непорожнім base64`);
	}
}

// { key, password, data, detached=true, cert?, tsp="signature", time? } → { signature, signer }
app.post("/api/sign", async (req, res) => {
	try {
		const { key, password, data, detached = true, cert = null, tsp = "signature", time = null } =
			req.body || {};
		if (!key || !data) {
			return res.status(400).json({ error: "Обовʼязкові поля: key (base64), data (base64)" });
		}
		const result = await sign(b64("key", key), password, b64("data", data), {
			detached: Boolean(detached),
			certBuffer: cert ? b64("cert", cert) : null,
			tsp: tsp === false || tsp === "none" ? false : tsp,
			time: time || null,
		});
		res.json({
			signature: result.signature.toString("base64"),
			signer: result.signer,
		});
	} catch (err) {
		const status = err instanceof SignerError ? 400 : 500;
		console.error("[sign]", err.message);
		res.status(status).json({ error: err.message });
	}
});

// { data } (attached CMS, base64) → { content, signer }
app.post("/api/unwrap", async (req, res) => {
	try {
		const { data } = req.body || {};
		if (!data) return res.status(400).json({ error: "Обовʼязкове поле: data (base64)" });
		const info = await unwrap(b64("data", data));
		res.json({
			content: info.content ? info.content.toString("base64") : null,
			signed_by: (info.signed && info.signed_by) || info.signedBy || null,
		});
	} catch (err) {
		console.error("[unwrap]", err.message);
		res.status(400).json({ error: err.message });
	}
});

app.listen(PORT, () => {
	console.log(`[prro-signer] listening on :${PORT}`);
});
