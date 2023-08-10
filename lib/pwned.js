'use strict';

const crypto = require('crypto');
const fetch = require('node-fetch');

const winston = require.main.require('winston');

/**
 * Checks if the specified password has been pwned.
 * @param {string} password The password to check.
 * @returns {Promise<boolean>} Whether the password is pwned or not.
 */
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

/**
 * Checks if the specified password has been pwned, and throws an error if it has.
 * @param {string} password The password to check.
 * @throws Will throw if the password has been pwned.
 */
exports.checkAndThrow = async (password) => {
	const isPwned = await this.check(password);
	if (isPwned) {
		throw new Error('[[pwned-passwords:error.exposed-password]]');
	}
};
