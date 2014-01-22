var vows = require('vows');
var assert = require('assert');

var Token = require('../lib/token');

var SERVER_KEY = 'someverysecurekey';
var VALID = {user: 'test@example.com', data: [{pos: 'first'}, {pos: 'second'}]};

vows.describe('Token').addBatch({
	"Given a user and some data": {
		topic: VALID,
		"when encoded into a token": {
			topic: function (d) {
				var t = new Token(d.user, expireIn(5000), d.data, {key: SERVER_KEY});
				return t.toSecureString();
			},
			"must return no errors": function (e, str) {
				assert.isNull(e);
			},
			"must return a Base64 encoded string": function (str) {
				assert.isString(str);
				assert.isNull(str.match(/[^A-Za-z0-9=\/]/g));
			}
		}
	}
}).addBatch({
	"Given a valid token": {
		topic: (new Token(VALID.user, expireIn(5000), VALID.data, {key: SERVER_KEY})).toSecureString(),
		"when decoded": {
			topic: function (str) {
				return Token.fromSecureString(str, {key: SERVER_KEY});
			},
			"must not throw any errors": function (e, t) {
				assert.isNull(e);
			},
			"must return an instance of Token": function (t) {
				assert.instanceOf(t, Token);
			},
			"must be valid": function (t) {
				assert.deepEqual(t._errors, []);
				assert.isTrue(t.isValid);
			},
			"must contain the username": function (t) {
				assert.strictEqual(t.user, VALID.user);
			},
			"must have the encoded data": function (t) {
				assert.deepEqual(t.data, VALID.data);
			}
		}
	}
}).addBatch({
	"Given an expired token": {
		topic: (new Token(VALID.user, expireIn(-5000), VALID.data, {key: SERVER_KEY})).toSecureString(),
		"when decoded": {
			topic: function (str) {
				return Token.fromSecureString(str, {key: SERVER_KEY});
			},
			"must not throw any errors": function (e, t) {
				assert.isNull(e);
			},
			"must return an instance of Token": function (t) {
				assert.instanceOf(t, Token);
			},
			"must not be valid": function (t) {
				assert.isFalse(t.isValid);
				assert.ok(t._errors.length);
			},
			"must contain the username": function (t) {
				assert.strictEqual(t.user, VALID.user);
			},
			"must not have the encoded data": function (t) {
				assert.isUndefined(t.data);
			}
		}
	}
}).addBatch({
	"Given a tempered token": {
		topic: function () {
			var tok = (new Token(VALID.user, expireIn(5000), VALID.data, {key: SERVER_KEY}));
			tok.initKey().encrypt().sign();
			tok.user = 'test@example2.com';
			return new Buffer([tok.user, tok.until, tok.crypted, tok.sig].join('|'), 'utf-8').toString('base64');
		},
		"when decoded": {
			topic: function (str) {
				return Token.fromSecureString(str, {key: SERVER_KEY});
			},
			"must not throw any errors": function (e, t) {
				assert.isNull(e);
			},
			"must return an instance of Token": function (t) {
				assert.instanceOf(t, Token);
			},
			"must not be valid": function (t) {
				assert.isFalse(t.isValid);
				assert.ok(t._errors.length);
			},
			"must contain the username": function (t) {
				assert.strictEqual(t.user, 'test@example2.com');
			},
			"must not have the encoded data": function (t) {
				assert.isUndefined(t.data);
			}
		}
	}
}).export(module);

function expireIn (msec) {
	var exp = new Date();
	exp.setMilliseconds(exp.getMilliseconds() + msec);
	return exp;
};
