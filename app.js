// app.js
const addon = require('./build/Release/ECIES');

const obj = new addon.ECIESWrapper(10);

var keys = obj.generateKeys();
console.log(`pub.x : ${keys.pub.x.toString('hex')}, pub.y : ${keys.pub.y.toString('hex')}, priv : ${keys.priv.toString('hex')}`);

console.log(obj.getKeys());


// setInterval(function() {
//     // obj.encrypt(new Buffer.from("asdfasdfab"));
//     var data = "length";
//     length = Buffer.byteLength(data);
//     var buf = new Buffer(length);
//     buf.write(data, 0, 'UTF8');

//     obj.encrypt(buf);
// }, 100);

// console.log(obj.encrypt(new Buffer.from("asdfasdf")).toString());


// obj.getGazePoint((pupil) => {
//     console.log(pupil);
// });