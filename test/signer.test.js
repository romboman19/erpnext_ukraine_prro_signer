"use strict";

const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const test = require("node:test");
const { sign, unwrap, isPrivateAddress } = require("../signer");

const DATA_DIR = path.join(__dirname, "..", "node_modules", "jkurwa", "test", "data");
const key = fs.readFileSync(path.join(DATA_DIR, "PRIV1.cer"));
const cert = fs.readFileSync(path.join(DATA_DIR, "SELF_SIGNED1.cer"));
const payload = Buffer.from("<CHECK><TEST>ПРРО тестовий чек</TEST></CHECK>", "utf-8");
const TEST_TIME = 1641111111;

test("attached CMS roundtrip preserves content and verifies signature", async () => {
	const result = await sign(key, null, payload, {
		detached: false,
		certBuffer: cert,
		time: TEST_TIME,
		tsp: false,
	});
	const info = await unwrap(result.signature);
	assert.deepEqual(Buffer.from(info.content), payload);
	assert.ok(result.signer);
});

test("detached CMS is produced", async () => {
	const result = await sign(key, null, payload, {
		detached: true,
		certBuffer: cert,
		time: TEST_TIME,
		tsp: false,
	});
	assert.ok(result.signature.length > 100);
});

test("certificate without TSP address fails explicitly", async () => {
	await assert.rejects(
		() => sign(key, null, payload, { detached: false, certBuffer: cert, time: TEST_TIME, tsp: "signature" }),
		/TSP/
	);
});

test("content timestamp modes are rejected for PRRO", async () => {
	await assert.rejects(
		() => sign(key, null, payload, { detached: false, certBuffer: cert, time: TEST_TIME, tsp: "content" }),
		/signature-time-stamp/
	);
});

test("tampered attached CMS fails cryptographic verification", async () => {
	const result = await sign(key, null, payload, {
		detached: false,
		certBuffer: cert,
		time: TEST_TIME,
		tsp: false,
	});
	const tampered = Buffer.from(result.signature);
	tampered[tampered.length - 16] ^= 0x01;
	await assert.rejects(() => unwrap(tampered));
});

test("TSP SSRF guard blocks private and metadata addresses", () => {
	assert.equal(isPrivateAddress("127.0.0.1"), true);
	assert.equal(isPrivateAddress("10.0.0.1"), true);
	assert.equal(isPrivateAddress("169.254.169.254"), true);
	assert.equal(isPrivateAddress("192.168.1.1"), true);
	assert.equal(isPrivateAddress("8.8.8.8"), false);
});
