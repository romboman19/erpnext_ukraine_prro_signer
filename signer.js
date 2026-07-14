"use strict";

const http = require("http");
const https = require("https");
const dns = require("dns");
const net = require("net");
const { URL } = require("url");

const gost89 = require("gost89");
const jk = require("jkurwa");

const algos = gost89.compat.algos;

const TSP_TIMEOUT_MS = Number(process.env.TSP_TIMEOUT_MS || 15000);
const TSP_MAX_RESPONSE_BYTES = Number(process.env.TSP_MAX_RESPONSE_BYTES || 1024 * 1024);

function isPrivateAddress(address) {
	if (net.isIPv4(address)) {
		const octets = address.split(".").map(Number);
		return (
			octets[0] === 0 ||
			octets[0] === 10 ||
			octets[0] === 127 ||
			(octets[0] === 169 && octets[1] === 254) ||
			(octets[0] === 172 && octets[1] >= 16 && octets[1] <= 31) ||
			(octets[0] === 192 && octets[1] === 168) ||
			(octets[0] === 100 && octets[1] >= 64 && octets[1] <= 127) ||
			octets[0] >= 224
		);
	}
	if (net.isIPv6(address)) {
		const value = address.toLowerCase();
		return (
			value === "::" ||
			value === "::1" ||
			value.startsWith("fc") ||
			value.startsWith("fd") ||
			/^fe[89ab]/.test(value)
		);
	}
	return true;
}

function safeLookup(hostname, options, callback) {
	dns.lookup(hostname, { all: true, verbatim: true }, (error, addresses) => {
		if (error) return callback(error);
		if (!addresses.length || addresses.some(({ address }) => isPrivateAddress(address))) {
			return callback(new Error("TSP hostname resolves to a private or unsafe address"));
		}
		if (options && options.all) return callback(null, addresses);
		return callback(null, addresses[0].address, addresses[0].family);
	});
}

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
	if (!['http:', 'https:'].includes(u.protocol)) return cb(null);
	if (!u.hostname || (net.isIP(u.hostname) && isPrivateAddress(u.hostname))) return cb(null);
	const lib = u.protocol === "https:" ? https : http;
	let finished = false;
	const done = (value) => {
		if (finished) return;
		finished = true;
		cb(value);
	};
	const req = lib.request(
		{
			method,
			hostname: u.hostname,
			port: u.port || (u.protocol === "https:" ? 443 : 80),
			path: u.pathname + u.search,
			headers,
			timeout: TSP_TIMEOUT_MS,
			lookup: safeLookup,
		},
		(res) => {
			const chunks = [];
			let length = 0;
			res.on("data", (chunk) => {
				length += chunk.length;
				if (length > TSP_MAX_RESPONSE_BYTES) {
					res.destroy();
					done(null);
					return;
				}
				chunks.push(chunk);
			});
			res.on("end", () => done(res.statusCode >= 200 && res.statusCode < 300 ? Buffer.concat(chunks) : null));
		}
	);
	req.on("error", () => done(null));
	req.on("timeout", () => {
		req.destroy();
		done(null);
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
	try {
		box.load({ keyBuffers: [keyBuffer], password: password || undefined });
	} catch (_error) {
		throw new SignerError("Не вдалося прочитати контейнер ключа: перевірте формат і пароль");
	}
	if (certBuffer) {
		try {
			box.load({ certPem: certBuffer });
		} catch (_error) {
			throw new SignerError("Не вдалося прочитати сертифікат підписувача");
		}
	}
	if (!box.keys || !box.keys.length) {
		throw new SignerError("У контейнері не знайдено приватних ключів (або хибний пароль)");
	}
	if (!box.keys.some((key) => key.cert)) {
		throw new SignerError(
			"Не знайдено сертифікат підписувача. ДПС вимагає включати його до CAdES-повідомлення"
		);
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
 * @param {string|false} [opts.tsp]   мітка часу: "signature" (CAdES-E-T, за замовч.,
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
	if (!Buffer.isBuffer(data) || !data.length) throw new SignerError("Дані для підпису порожні");
	if (![false, "signature"].includes(tsp)) {
		throw new SignerError(
			'Підтримується лише signature-time-stamp (tsp:"signature") або підпис без TSP (tsp:false)'
		);
	}
	const box = createBox(keyBuffer, password, certBuffer);
	try {
		const key = box.keys.find((candidate) => candidate.cert) || box.keys[0];
		if (!time && key.cert && key.cert.valid) {
			const validFrom = new Date(key.cert.valid.from);
			const validTo = new Date(key.cert.valid.to);
			if (Number.isFinite(validFrom.getTime()) && validFrom.getTime() > Date.now()) {
				throw new SignerError(`Сертифікат підписувача ще не набув чинності (${validFrom.toISOString()})`);
			}
			if (Number.isFinite(validTo.getTime()) && validTo.getTime() <= Date.now()) {
				throw new SignerError(`Сертифікат підписувача прострочений (${validTo.toISOString()})`);
			}
		}
		if (tsp) {
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
		if (tsp) op.tsp = tsp; // "signature" → signature-time-stamp (CAdES-E-T)
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
	if (!Buffer.isBuffer(signedData) || !signedData.length) {
		throw new SignerError("Підписаний блок порожній");
	}
	const box = new jk.Box({ algo: algos() });
	const info = await box.unwrap(signedData);
	const pipeInfo = info && info.pipe && info.pipe[0];
	if (!info || (pipeInfo && pipeInfo.error)) {
		throw new SignerError("Криптографічна перевірка підписаного блока не пройдена");
	}
	return info;
}

module.exports = { sign, unwrap, SignerError, isPrivateAddress, safeLookup };
