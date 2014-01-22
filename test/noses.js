var vows = require('vows');
var assert = require('assert');
var noses = require('../lib/noses');
var http = require('http');

var SERVER_KEY = 'someverysecurekey';
var VALID = {user: 'test@example.com', data: [{pos: 'first'}, {pos: 'second'}]};
var PORT = process.env.PORT || 3001;

vows.describe('noses').addBatch({
	"Given a server": {
		topic: function () {
			var parser = noses.parser({key: SERVER_KEY, httpOnly: true, name: '_nsd', expires: 120}, function (q,r) {
				if (q._noses) {
					r.writeHead(200);
					r.end(JSON.stringify(q._noses));
				} else {
					q.noses.set(r, VALID.user, VALID.data);
					r.writeHead(200);
					r.end('{}');
				}
			});
			var s = http.createServer(function (q,r) {
				r.setHeader('Content-Type', 'application/json');
				parser(q,r);
			});
			s.listen(PORT, this.callback);
		},
		"when connecting": {
			topic: function () {
				var cb = this.callback;
				var c = {hostname: 'localhost', port: PORT, path: '/'};
				http.get(c, function (res) {
					cb(null, res.headers['set-cookie'][0]);
				});
			},
			"must reply with a cookie": function (err, cookie) {
				assert.isNull(err);
				assert.isString(cookie);
			},
			"and replaying the cookie": {
				topic: function (cookie) {
					var cb = this.callback;
					var c = {hostname: 'localhost', port: PORT, path: '/', headers: {'Cookie': cookie}};
					http.get(c, function (res) {
						var buf = '';
						res.on('data', function (c) { buf += c.toString('utf-8'); });
						res.on('end', function () {
							cb(null, buf, res.headers);
						});
					});
				},
				"must not throw an error": function (e,b,h) {
					assert.isNull(e);
				},
				"must return a string body": function (e,b,h) {
					assert.isString(b);
				},
				"must show a valid cookie": function (e,b,h) {
					var c = JSON.parse(b);
					assert.isObject(c);
					assert.isTrue(c.isValid);
					assert.strictEqual(c.user, VALID.user);
					assert.strictEqual(c._data, JSON.stringify(VALID.data));
				}
			}
		}
	}
}).export(module);
