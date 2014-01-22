NoSes
======
Token/Cookie provider for session-less node.js apps

### Installlation
```
npm install noses
```

### Usage

#### Creating a token
```javascript
var NoSes = require('noses');
var noses = new NoSes({key: 'mysecurekey'});
noses.createToken('user id', {user: 'data'}, function (error, token) {
    console.log(error || token);
});
```

#### Parsing and validating a token
```javascript
var NoSes = require('noses');
var noses = new NoSes({key: 'mysecurekey'});
noses.parseToken('token', function (error, parsedToken) {
    console.log(error || parsedToken);
});
```
