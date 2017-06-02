// app.js
const addon = require('./build/Release/ECIES');

const obj = new addon.ECIESWrapper(10);

var serverKeys = {
    pub: {
        x: new Buffer('07da0243df3bd7e78d8c9f746bd108ddc3536e937b', 'hex'),
        y: new Buffer('036c175abe8d80125c890ef123cfddb89e59f0e9d0', 'hex')
    },
    priv: new Buffer('00944a495cffb0dc513348733c98697b23c68b4567', 'hex')
};

var clientKeys = {
    pub: {
        x: new Buffer('07da0243df3bd7e78d8c9f746bd108ddc3536e937b', 'hex'),
        y: new Buffer('036c175abe8d80125c890ef123cfddb89e59f0e9d0', 'hex')
    },
    priv: new Buffer('00944a495cffb0dc513348733c98697b23c68b4567', 'hex')
};

// Generate new public and private keys
// var keys = obj.generateKeys();
// console.log(`pub.x : ${keys.pub.x.toString('hex')}, pub.y : ${keys.pub.y.toString('hex')}, priv : ${keys.priv.toString('hex')}`);

// Get public and private keys
// console.log(obj.getKeys());

// Set public keys, must be 21 bytes each
console.log(obj.setClientPublicKey(clientKeys.pub.x, clientKeys.pub.y));
console.log(obj.setPrivateKey(serverKeys.priv));

// Encryption
var data = "test text";
var length = Buffer.byteLength(data);
var buf = new Buffer(length);
buf.write(data, 0, 'UTF8');
var encrypted = obj.encrypt(buf, buf);
console.log(encrypted.toString('hex'));



// obj.getGazePoint((pupil) => {
//     console.log(pupil);
// });