"use strict";

const http = require("http");
const https = require("https");
const { URL } = require("url");

const gost89 = require("gost89");
const jk = require("jkurwa");

const algos = gost89.compat.algos;

const TSP_TIMEOUT_MS = Number(process.env.TSP_TIMEOUT_MS || 15000);

/**
 * HTTP-клієнт для jkurwa (запити до TSP-сервера КНЕДП при формуванні мітки часу).
 * jkurwa викликає query(method, url, headers, body, cb); cb отримує тіло
 * відповіді (Buffer) або null у разі помилки.
 */
function query(method, url, headers, body, cb) {
	let u;
	try {
		u = new URL(url);
	} catch (e) {
		return cb(null);
	}
	const lib = u.protocol === "https:" ? https : http;
	const req = lib.request(
		{
			method,
			hostname: u.hostname,
			port: u.port || (u.protocol === "https:" ? 443 : 80),
			path: u.pathname + u.search,
			headers,
			timeout: TSP_TIMEOUT_MS,
		},
		(res) => {
			const chunks = [];
			res.on("data", (c) => chunks.push(c));
			res.on("end", () => cb(Buffer.concat(chunks)));
		}
	);
	req.on("error", () => cb(null));
	req.on("timeout", () => {
		req.destroy();
		cb(null);
	});
	if (body) req.write(body);
	req.end();
}

/**
 * Створює Box із файловим ключем. Ключ живе лише в памʼяті запиту.
 *
 * @param {Buffer} keyBuffer  контейнер ключа (JKS / Key-6.dat / PEM / DER)
 * @param {string} [password] пароль контейнера
 * @param {Buffer} [certBuffer] сертифікат, якщо його немає в контейнері
 */
function createBox(keyBuffer, password, certBuffer) {
	const box = new jk.Box({ algo: algos(), query });
	box.load({ keyBuffers: [keyBuffer], password: password || undefined });
	if (certBuffer) {
		box.load({ certPem: certBuffer });
	}
	if (!box.keys || !box.keys.length) {
		throw new SignerError("У контейнері не знайдено приватних ключів (або хибний пароль)");
	}
	return box;
}

class SignerError extends Error {}

function signerInfo(box) {
	const key = box.keys.find((k) => k.cert) || box.keys[0];
	if (!key.cert) return null;
	const cert = key.cert;
	const subject = cert.subject || {};
	const extension = cert.extension || {};
	return {
		subject_cn: subject.commonName || null,
		organization: subject.organizationName || null,
		serial: cert.format_pem ? undefined : undefined,
		ipn: (extension.ipn && extension.ipn.DRFO) || null,
		edrpou: (extension.ipn && extension.ipn.EDRPOU) || null,
		not_after: cert.valid && cert.valid.to ? new Date(cert.valid.to).toISOString() : null,
	};
}

/**
 * Підписує дані ДСТУ-4145 (CMS).
 *
 * @param {object}  opts
 * @param {boolean} [opts.detached]   відкріплений підпис (для ДПС — false, attached)
 * @param {Buffer}  [opts.certBuffer] сертифікат, якщо його немає в контейнері
 * @param {number}  [opts.time]       час підпису (unix seconds)
 * @param {string|false} [opts.tsp]   мітка часу: "signature" (CAdES-T, за замовч.,
 *   для онлайн-документів ДПС), "content", "all" або false (CAdES-BES, офлайн).
 *   Адреса TSP-сервера береться з сертифіката (subjectInfoAccess).
 * @returns {Promise<{signature: Buffer, signer: object}>}
 */
async function sign(
	keyBuffer,
	password,
	data,
	{ detached = true, certBuffer = null, time = null, tsp = "signature" } = {}
) {
	const box = createBox(keyBuffer, password, certBuffer);
	try {
		if (tsp) {
			const key = box.keys.find((k) => k.cert) || box.keys[0];
			const sia = key.cert && key.cert.extension && key.cert.extension.subjectInfoAccess;
			if (!sia || !sia.link) {
				throw new SignerError(
					"У сертифікаті немає адреси TSP-сервера (subjectInfoAccess) — " +
						"мітку часу сформувати неможливо. Для офлайн-документів передайте tsp:false."
				);
			}
		}
		const op = { op: "sign", detached: Boolean(detached), tax: false };
		if (time) op.time = time; // unix seconds; для тестів з простроченими сертифікатами
		if (tsp) op.tsp = tsp; // "signature" → signature-time-stamp (CAdES-T)
		let result;
		try {
			result = await box.pipe(data, [op]);
		} catch (e) {
			throw new SignerError(`Помилка формування підпису/мітки часу: ${e.message || e}`);
		}
		if (!result || result.error) {
			throw new SignerError(
				tsp
					? "Не вдалося отримати мітку часу від TSP-сервера КНЕДП (недоступний або відмовив)"
					: "Помилка формування підпису"
			);
		}
		return { signature: result, signer: signerInfo(box) };
	} finally {
		// не тримаємо ключ довше за запит
		if (box.keys) box.keys.length = 0;
	}
}

/**
 * Перевіряє attached CMS-підпис і повертає вміст + інформацію про підписанта.
 * Використовується для самотестування; без перевірки ланцюга CA.
 */
async function unwrap(signedData) {
	const box = new jk.Box({ algo: algos() });
	const info = await box.unwrap(signedData);
	return info;
}

module.exports = { sign, unwrap, SignerError };
