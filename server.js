"use strict";

const crypto = require("crypto");
const express = require("express");
const { sign, unwrap, SignerError } = require("./signer");

const PORT = Number(process.env.PORT || 8080);
const KEY_MAX_BYTES = Number(process.env.KEY_MAX_BYTES || 5 * 1024 * 1024);
const CERT_MAX_BYTES = Number(process.env.CERT_MAX_BYTES || 2 * 1024 * 1024);
const DATA_MAX_BYTES = Number(process.env.DATA_MAX_BYTES || 1024 * 1024);
const MAX_CONCURRENT_REQUESTS = Number(process.env.MAX_CONCURRENT_REQUESTS || 4);

function safeEqual(left, right) {
	const a = Buffer.from(String(left || ""));
	const b = Buffer.from(String(right || ""));
	return a.length === b.length && a.length > 0 && crypto.timingSafeEqual(a, b);
}

function b64(field, value, maxBytes) {
	if (typeof value !== "string" || !value.length || value.length % 4 !== 0 || !/^[A-Za-z0-9+/]+={0,2}$/.test(value)) {
		throw new SignerError(`Поле ${field} має бути непорожнім base64`);
	}
	const buffer = Buffer.from(value, "base64");
	if (!buffer.length || buffer.toString("base64") !== value) {
		throw new SignerError(`Поле ${field} має бути канонічним base64`);
	}
	if (buffer.length > maxBytes) throw new SignerError(`Поле ${field} перевищує дозволений розмір`);
	return buffer;
}

function createApp(apiKey = process.env.API_KEY) {
	if (!apiKey || String(apiKey).length < 32) {
		throw new Error("API_KEY env variable is required and must contain at least 32 characters");
	}
	const app = express();
	app.disable("x-powered-by");
	app.use(express.json({ limit: "12mb", strict: true, type: "application/json" }));
	app.use((req, res, next) => {
		res.set("Cache-Control", "no-store");
		res.set("X-Content-Type-Options", "nosniff");
		req.requestId = req.get("x-request-id") || crypto.randomUUID();
		res.set("X-Request-ID", req.requestId);
		next();
	});

	app.get("/health", (_req, res) => {
		res.json({ status: "ok", service: "erpnext-ukraine-prro-signer", uptime: process.uptime() });
	});

	app.use((req, res, next) => {
		if (!safeEqual(req.get("x-api-key"), apiKey)) {
			return res.status(401).json({ error: "unauthorized" });
		}
		next();
	});
	let activeRequests = 0;
	app.use("/api", (req, res, next) => {
		if (activeRequests >= MAX_CONCURRENT_REQUESTS) {
			return res.status(503).json({ error: "signer_busy", request_id: req.requestId });
		}
		activeRequests += 1;
		let released = false;
		const release = () => {
			if (released) return;
			released = true;
			activeRequests -= 1;
		};
		res.once("finish", release);
		res.once("close", release);
		next();
	});

	app.post("/api/sign", async (req, res) => {
		try {
			const { key, password, data, detached = true, cert = null, tsp = "signature", time = null } = req.body || {};
			if (!key || !data) {
				return res.status(400).json({ error: "Обовʼязкові поля: key (base64), data (base64)" });
			}
			if (typeof detached !== "boolean") throw new SignerError("Поле detached має бути boolean");
			if (password != null && (typeof password !== "string" || password.length > 1024)) {
				throw new SignerError("Поле password має бути рядком до 1024 символів");
			}
			if (time && process.env.ALLOW_TEST_TIME !== "1") {
				throw new SignerError("Довільний час підпису вимкнений");
			}
			const normalizedTsp = tsp === false || tsp === "none" ? false : tsp;
			const result = await sign(b64("key", key, KEY_MAX_BYTES), password, b64("data", data, DATA_MAX_BYTES), {
				detached,
				certBuffer: cert ? b64("cert", cert, CERT_MAX_BYTES) : null,
				tsp: normalizedTsp,
				time: time || null,
			});
			res.json({ signature: result.signature.toString("base64"), signer: result.signer });
		} catch (error) {
			const status = error instanceof SignerError ? 400 : 500;
			console.error(`[sign:${req.requestId}]`, error.message);
			res.status(status).json({ error: error.message, request_id: req.requestId });
		}
	});

	app.post("/api/unwrap", async (req, res) => {
		try {
			const { data } = req.body || {};
			if (!data) return res.status(400).json({ error: "Обовʼязкове поле: data (base64)" });
			const info = await unwrap(b64("data", data, DATA_MAX_BYTES * 2));
			const verified = (info.pipe || []).find((entry) => entry && entry.signed && !entry.error);
			if (!verified) throw new SignerError("Підписувача CMS не знайдено або підпис некоректний");
			res.json({
				content: info.content ? info.content.toString("base64") : null,
				signed_by: verified.cert ? {
					common_name: verified.cert.subject && verified.cert.subject.commonName,
					issuer: verified.cert.issuer && verified.cert.issuer.commonName,
					valid_from: verified.cert.valid && verified.cert.valid.from,
					valid_to: verified.cert.valid && verified.cert.valid.to,
				} : null,
				signature_timestamp: verified.tokenTime || null,
				cryptographically_verified: true,
			});
		} catch (error) {
			console.error(`[unwrap:${req.requestId}]`, error.message);
			res.status(400).json({ error: error.message, request_id: req.requestId });
		}
	});

	app.use((error, req, res, _next) => {
		const status = error.type === "entity.too.large" ? 413 : 400;
		res.status(status).json({ error: status === 413 ? "request_too_large" : "invalid_json", request_id: req.requestId });
	});
	return app;
}

if (require.main === module) {
	let server;
	try {
		server = createApp().listen(PORT, () => console.log(`[prro-signer] listening on :${PORT}`));
		server.requestTimeout = 30_000;
		server.headersTimeout = 15_000;
	} catch (error) {
		console.error(`[prro-signer] ${error.message}`);
		process.exit(1);
	}
	for (const signal of ["SIGTERM", "SIGINT"]) {
		process.on(signal, () => server.close(() => process.exit(0)));
	}
}

module.exports = { createApp, safeEqual, b64 };
