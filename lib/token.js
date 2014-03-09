var crypto = require('crypto');

var Token = module.exports = function (user, until, data, opts) {
	Object.defineProperty(this, 'opts', {
		value: opts,
		enumerable: false,
		writable: false
	});

	this.user = user;
	this.until = (until instanceof Date) ? until.getTime() : until;
	this._errors = [];

	var tok = this;
	Object.defineProperty(this, 'data', {
		enumerable: false,
		configurable: true,
		get: function () { return (tok._data !== undefined && tok.isValid) ? JSON.parse(tok._data) : undefined; },
		set: function (d) { if (d !== undefined) tok._data = JSON.stringify(d); }
	});

	Object.defineProperty(this, 'isValid', {
		enumerable: true,
		configurable: false,
		get: function () { return this._errors.length === 0; },
		set: function () { /* do nothing */ }
	});

	this.data = data;
};

Token.prototype.initKey = function () {
	if (!this.isValid) return this;
	Object.defineProperty(this, 'k', {
		value: this.makeKey(),
		enumerable: false,
		writable: false,
		configurable: false
	});
	return this;
};

Token.prototype.makeKey = function () {
	return crypto.createHmac('sha256', this.opts.key).update([this.user,this.until].join('|')).digest();
};

Token.prototype.encrypt = function () {
	if (this._data === undefined) {
		this.crypted = '';
		return this;
	}
	var err = null;
	try {
		var c = crypto.createCipher('aes256', this.k);
		var cted = [c.update(new Buffer(this._data, 'utf-8'))];
		cted.push(c.final());
		this.crypted = Buffer.concat(cted).toString('base64');
	} catch (e) {
		err = e;
		this.crypted = undefined;
	}
	return (err) ? this.setError(err) : this;
};

Token.prototype.decrypt = function (crypted) {
	if (!this.isValid) return this;
	var cdat = crypted || this.crypted;
	if (cdat === '' || cdat === undefined) {
		return this;
	}
	var err = null;
	try {
		var c = crypto.createDecipher('aes256', this.k);
		var dcted = [c.update(new Buffer(crypted || this.crypted, 'base64'))];
		dcted.push(c.final());
		this._data = Buffer.concat(dcted).toString('utf-8');
	} catch (e) {
		err = e;
		this._data = undefined;
	}
	return (err) ? this.setError(err) : this;
};

Token.prototype.sign = function () {
	if (!this.isValid) return this;
	this.sig = crypto.createHmac('sha256', this.k).update([this.user, this.until, this._data].join('|')).digest('base64');
	return this;
};

Token.prototype.setError = function (err, prio) {
	var t = (prio) ? this._errors.unshift(err) : this._errors.push(err);
	return this;
};

Token.prototype.expiryDate = function () {
	return new Date(parseInt(this.until, 10));
};

Token.prototype.checkExpiry = function () {
	return (this.expiryDate() > new Date()) ? this : this.setError(new Error('Token is expired'), 1);
};

Token.prototype.match = function (sig) {
	return (this.sign().sig === sig) ? this : this.setError(new Error('Signature doesn\'t match'), 1);
};

Token.prototype.toSecureString = function () {
	this.initKey().encrypt().sign();
	var out = [this.user, this.until, this.crypted, this.sig].join('|');
	return new Buffer(out, 'utf-8').toString('base64');
};

Token.fromSecureString = function (str, opts) {
	var data = (new Buffer(str, 'base64')).toString('utf-8').split('|');
	return (new Token(data[0], data[1], undefined, opts)).checkExpiry().initKey().decrypt(data[2]).match(data[3]);
};
