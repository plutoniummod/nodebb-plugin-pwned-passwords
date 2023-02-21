'use strict';

const crypto = require('crypto');
const fetch = require('node-fetch');

const winston = require.main.require('winston');

exports.check = async (password) => {
	// Hash password
	const sha1 = crypto.createHash('sha1');
	sha1.update(password);
	const hash = sha1.digest('hex').toUpperCase();

	// Check hash against API
	try {
		const response = await fetch(`https://api.pwnedpasswords.com/range/${hash.substring(0, 5)}`, { timeout: 2500 });
		const body = await response.text();
		const pwnedHashes = new Map(body.split(/\r?\n/).map(l => l.split(':')));

		return pwnedHashes.has(hash.substring(5));
	} catch (error) {
		winston.warn(`[plugins/pwned-passwords] Failed to check password: ${error}`);
	}

	return false;
};
