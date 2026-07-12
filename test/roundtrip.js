"use strict";

/*
 * PoC roundtrip: підписуємо тестовим ключем із фікстур jkurwa
 * (PRIV1.cer + SELF_SIGNED1.cer) і розгортаємо attached-підпис назад.
 */

const fs = require("fs");
const path = require("path");
const { sign, unwrap } = require("../signer");

const DATA_DIR = path.join(__dirname, "..", "node_modules", "jkurwa", "test", "data");

async function main() {
	const keyBuf = fs.readFileSync(path.join(DATA_DIR, "PRIV1.cer"));
	const certBuf = fs.readFileSync(path.join(DATA_DIR, "SELF_SIGNED1.cer"));
	const payload = Buffer.from("<CHECK><TEST>ПРРО тестовий чек</TEST></CHECK>", "utf-8");

	// час підпису в межах дії тестового сертифіката (січень 2022)
	const TEST_TIME = 1641111111;

	// attached-підпис БЕЗ TSP (CAdES-BES) — фікстурний сертифікат не має TSP-адреси.
	// Онлайн-документи ДПС вимагають tsp:"signature" (CAdES-T) з реальним ключем.
	const attached = await sign(keyBuf, null, payload, {
		detached: false,
		certBuffer: certBuf,
		time: TEST_TIME,
		tsp: false,
	});
	console.log("attached signature bytes:", attached.signature.length);
	console.log("signer:", JSON.stringify(attached.signer));

	const info = await unwrap(attached.signature);
	const pipeInfo = info.pipe && info.pipe[0];
	if (pipeInfo && pipeInfo.error) {
		console.error("FAIL: signature did not verify:", JSON.stringify(pipeInfo));
		process.exit(1);
	}
	const content = info.content;
	if (!content || Buffer.compare(Buffer.from(content), payload) !== 0) {
		console.error("FAIL: unwrapped content does not match original");
		process.exit(1);
	}
	console.log("attached roundtrip: OK (signature verified, content matches)");

	// detached-підпис (теж BES для фікстури)
	const detached = await sign(keyBuf, null, payload, {
		detached: true,
		certBuffer: certBuf,
		time: TEST_TIME,
		tsp: false,
	});
	console.log("detached signature bytes:", detached.signature.length);
	if (detached.signature.length >= attached.signature.length) {
		console.warn("WARN: detached signature is not smaller than attached — перевірити");
	}

	// tsp:"signature" на сертифікаті без TSP-адреси → зрозуміла помилка (не мовчазний збій)
	let tspErr = null;
	try {
		await sign(keyBuf, null, payload, { detached: false, certBuffer: certBuf, time: TEST_TIME,
			tsp: "signature" });
	} catch (e) {
		tspErr = e.message;
	}
	if (!tspErr || !tspErr.includes("TSP")) {
		console.error("FAIL: очікувалась зрозуміла TSP-помилка, отримано:", tspErr);
		process.exit(1);
	}
	console.log("TSP guard OK:", tspErr.slice(0, 60), "...");
	console.log("ALL OK");
}

main().catch((err) => {
	console.error("FAIL:", err);
	process.exit(1);
});
