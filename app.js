// app.js
const addon = require('./build/Release/ECIES');
var assert = require('assert');

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

setInterval(function() {
    // Encryption
    // var data = "test text";
    // var length = Buffer.byteLength(data);
    // var buf = new Buffer(length);
    // buf.write(data, 0, 'UTF8');

    var buf = new Buffer([0x10, 0x23, 0x52, 0x49, 0x5c, 0xff, 0xb0, 0xdc, 0x51, 0x33, 0x48, 0x73, 0x3c, 0x98, 0x69, 0x7b, 0x23, 0x78, 0xab, 0xcd, 0xef]);

    var encrypted = obj.encrypt(buf);
    // console.log(encrypted.toString('hex'));

    // Decryption 처음 인크립션한 길이를 알아야 디크립션이 가능함
    var decrypted = obj.decrypt(encrypted, Buffer.byteLength(buf));

    if (decrypted) {
        console.log('yes');
        console.log(decrypted);
    } else {
        console.log('no');
    }

    // assert.deepEqual(decrypted, buf);

}, 500);




// obj.getGazePoint((pupil) => {
//     console.log(pupil);
// });