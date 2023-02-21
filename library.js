'use strict';

const User = require.main.require('./src/user');

const pwned = require('./lib/pwned');

exports.registerCheck = async (data) => {
	const { userData } = data;

	const isPwned = await pwned.check(userData.password);
	if (isPwned) {
		throw new Error('[[pwned-passwords:exposed-password]]');
	}

	return data;
};

// Hook User.changePassword directly since no plugin hook exists
// https://github.com/NodeBB/NodeBB/blob/edd2fc38fc2d6f0ff7f344d11236190a44404f5d/src/user/profile.js#L293
const originalChangePassword = User.changePassword;
User.changePassword = async function (uid, data) {
	const isPwned = await pwned.check(data.newPassword);
	if (isPwned) {
		throw new Error('[[pwned-passwords:exposed-password]]');
	}

	await originalChangePassword(uid, data);
};
