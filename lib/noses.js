var Cookie = require('./cookie');
var Token = require('./token');

var NoSes = module.exports = function (opts) {
	Object.defineProperty(this, 'tokenOpts', {
		value: { key: opts && opts.key || 'noKeySpecified' },
		enumerable: false,
		writable: false,
		configurable: false
	});

	this.opts = mixin(NoSes.DEFAULT_OPTS, opts);
	this.cookie = new Cookie(this.opts);
};

NoSes.DEFAULT_OPTS = {
	name: '_nsd',
	expires: 24*60*60,
	httpOnly: true,
	secure: false,
	maxAge: false,
	domain: false,
	path: false
};

NoSes.Cookie = Cookie;
NoSes.Token = Token;

NoSes.prototype.createExpiry = function () {
	var until = new Date();
	until.setSeconds(until.getSeconds() + this.opts.expires);
	return until;
};

NoSes.prototype.parse = function (req) {
	if (!req.headers.cookie) return req;
	var cookieData = this.cookie.parse(req.headers.cookie);
	if (cookieData) req._noses = Token.fromSecureString(cookieData, this.tokenOpts);
	return req;
};

NoSes.prototype.set = function (res, user, data) {
	var exp = this.createExpiry();
	var t = new Token(user, exp, data, this.tokenOpts);
	return this.cookie.write(res, t.toSecureString(), exp);
};

NoSes.prototype.createToken = function (user, data, cb) {
	var token = new Token(user, this.createExpiry, data, this.tokenOpts);
	if (!token.isValid) return cb(token._errors[0]);
	cb(null, token.toSecureString());
};

NoSes.prototype.parseToken = function (str, cb) {
	var token = Token.fromSecureString(str, this.tokenOpts);
	return cb((!token.isValid) ? token._errors[0] : null, token);
};

NoSes.parser = function (opts, cb) {
	var n = new NoSes(opts);
	return function (req, res, next) {
		req.noses = n;
		n.parse(req);
		return (typeof(cb) === 'function') ? cb(req, res, next) : (typeof(next) === 'function') ? next(req, res) : req;
	};
};

function mixin (a,b) {
	if (!b || typeof(b) !== 'object') b = {};
	var out = {};
	Object.keys(a).forEach(function (k) {
		out[k] = (b.hasOwnProperty(k)) ? b[k] : a[k];
	});
	return out;
}
