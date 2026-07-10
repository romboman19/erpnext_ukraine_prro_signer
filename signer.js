"use strict";

const gost89 = require("gost89");
const jk = require("jkurwa");

const algos = gost89.compat.algos;

/**
 * Створює Box із файловим ключем. Ключ живе лише в памʼяті запиту.
 *
 * @param {Buffer} keyBuffer  контейнер ключа (JKS / Key-6.dat / PEM / DER)
 * @param {string} [password] пароль контейнера
 * @param {Buffer} [certBuffer] сертифікат, якщо його немає в контейнері
 */
function createBox(keyBuffer, password, certBuffer) {
	const box = new jk.Box({ algo: algos() });
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
 * Підписує дані ДСТУ-4145 (CMS/CAdES-BES).
 *
 * @returns {Promise<{signature: Buffer, signer: object}>}
 */
async function sign(keyBuffer, password, data, { detached = true, certBuffer = null, time = null } = {}) {
	const box = createBox(keyBuffer, password, certBuffer);
	try {
		const op = { op: "sign", detached: Boolean(detached), tax: false };
		if (time) op.time = time; // unix seconds; для тестів з простроченими сертифікатами
		const result = await box.pipe(data, [op]);
		if (!result || result.error) {
			throw new SignerError("Помилка формування підпису");
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
