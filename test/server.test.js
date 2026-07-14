"use strict";

const assert = require("node:assert/strict");
const test = require("node:test");
const { createApp } = require("../server");

const API_KEY = "test-api-key-with-at-least-32-characters";

async function withServer(fn) {
	const server = createApp(API_KEY).listen(0, "127.0.0.1");
	await new Promise((resolve) => server.once("listening", resolve));
	try {
		await fn(`http://127.0.0.1:${server.address().port}`);
	} finally {
		await new Promise((resolve) => server.close(resolve));
	}
}

test("health is public but signing API requires authentication", async () => {
	await withServer(async (baseUrl) => {
		const health = await fetch(`${baseUrl}/health`);
		assert.equal(health.status, 200);
		const denied = await fetch(`${baseUrl}/api/sign`, {
			method: "POST",
			headers: { "content-type": "application/json" },
			body: JSON.stringify({}),
		});
		assert.equal(denied.status, 401);
	});
});

test("non-canonical base64 is rejected", async () => {
	await withServer(async (baseUrl) => {
		const response = await fetch(`${baseUrl}/api/sign`, {
			method: "POST",
			headers: { "content-type": "application/json", "x-api-key": API_KEY },
			body: JSON.stringify({ key: "!!!!", data: "eA==" }),
		});
		assert.equal(response.status, 400);
		assert.match((await response.json()).error, /base64/);
	});
});

test("arbitrary signing time is disabled over HTTP", async () => {
	await withServer(async (baseUrl) => {
		const response = await fetch(`${baseUrl}/api/sign`, {
			method: "POST",
			headers: { "content-type": "application/json", "x-api-key": API_KEY },
			body: JSON.stringify({ key: "eA==", data: "eA==", time: 1 }),
		});
		assert.equal(response.status, 400);
		assert.match((await response.json()).error, /час/);
	});
});
