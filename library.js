'use strict';

const pwned = require('./lib/pwned');

exports.registerCheck = async (data) => {
	const { userData } = data;

	await pwned.checkAndThrow(userData.password);

	return data;
};

exports.passwordCheck = async (data) => {
	const { password } = data;

	await pwned.checkAndThrow(password);

	return data;
};
