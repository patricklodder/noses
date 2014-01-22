var Cookie = module.exports = function (opts) {
	Object.defineProperty(this, 'opts', {
		value: opts,
		enumerable: false,
		writable: false
	});
};

Cookie.prototype.write = function (res, data, expires) {
	if (res.headersSent) return false;
	res.setHeader('Set-Cookie', this.serialize(data, expires));
	return true;
};

Cookie.prototype.serialize = function (data, expires) {
	var pairs = [];

	pairs.push(Cookie._serializePair(this.opts.name, encodeURIComponent(data)));
	pairs.push(Cookie._serializePair('Expires', expires.toUTCString()));

    if (this.opts.maxAge) pairs.push(Cookie._serializePair('Max-Age', this.opts.maxAge));
    if (this.opts.domain) pairs.push(Cookie._serializePair('Domain', this.opts.domain));
    if (this.opts.path) pairs.push(Cookie._serializePair('Path', this.opts.path));
    if (this.opts.httpOnly) pairs.push(Cookie._serializePair('HttpOnly'));
    if (this.opts.secure) pairs.push(Cookie._serializePair('Secure'));

    return pairs.join('; ');
};

Cookie.prototype.parse = function (data) {
	var sel = null;
	var name = this.opts.name;
	var pairs = data.split(/[;,]\s*/);
	pairs.some(function (p) {
		var m = p.split('=');
		if (m[0] !== name) return false;
		sel = m[1];
		return true;
	});
	return sel && decodeURIComponent(sel);
};

Cookie._serializePair = function (name, val) {
	return (val === undefined) ? name : [name,val].join('=');
};