const identicon = require("./identicon.js");
const qr        = require("qr-image");
const elliptic  = require("elliptic");
const sha3      = require("js-sha3");
const ethUtil   = require("ethereumjs-util");
const uuidv4    = require("uuid/v4");
const scrypt    = require("scryptsy");
const readline  = require("readline");
const crypto    = require("crypto");
const fs        = require("fs");

function EthWallet(){
  this.privateKeyBuffer = "";
  this.privateKeyString = "";
  this.publicKeyBuffer  = "";
  this.publicKeyString  = "";
  this.sha3Hash         = "";
  this.ethAddress       = "";
  this.userPassword     = "";
  this.generator        = elliptic.ec("secp256k1").g;

  if(!fs.existsSync("./wallets"))fs.mkdirSync("./wallets");
}

EthWallet.prototype.PromptUserForPassword = function(){return new Promise((resolve) => {
  var self = this;

  const rl = readline.createInterface({
    "input" : process.stdin,
    "output": process.stdout
  });

  rl.question("Enter a password to encrypt your private key: ", (answer) => {
    self.userPassword = answer;
    rl.close();
    resolve();
  });
})}

EthWallet.prototype.GetPrivateKey = function(){return new Promise((resolve) => {
  var self = this;
  self.privateKeyBuffer = crypto.randomBytes(32);
  self.privateKeyString = self.privateKeyBuffer.toString("hex");
  resolve();
})}

EthWallet.prototype.GetPublicKey = function(){return new Promise((resolve) => {
  var self = this;
  var pubPoint = self.generator.mul(self.privateKeyBuffer); // EC multiplication to determine public point
  var x = pubPoint.getX().toBuffer();                       // 32 bit x coordinate of public point
  var y = pubPoint.getY().toBuffer();                       // 32 bit y coordinate of public point
  self.publicKeyBuffer = Buffer.concat([x,y]);              // Get the public key in binary
  self.publicKeyString = self.publicKeyBuffer.toString("hex");
  resolve();
})}

EthWallet.prototype.GetEthAddress = function(){return new Promise((resolve) => {
  var self = this;
  self.sha3Hash   = sha3.keccak256(self.publicKeyBuffer);
  self.ethAddress = "0x" + self.sha3Hash.slice(-40);
  resolve();
})}

EthWallet.prototype.GetQrCodes = function(){return new Promise((resolve) => {
  var self = this;
  var qrPrivateKey = qr.image(self.privateKeyString);
  var qrEthAddress = qr.image(self.ethAddress);
  qrPrivateKey.pipe(fs.createWriteStream("wallets/private-key.png"));
  qrEthAddress.pipe(fs.createWriteStream("wallets/eth-address.png"));
  resolve();
})}

EthWallet.prototype.GetIdenticon = function(){return new Promise((resolve) => {
  var self = this;
  var icon = identicon.CreateIcon(self.ethAddress);
  fs.writeFileSync("wallets/identicon.png", icon);
  resolve();
})}

EthWallet.prototype.GetKeystoreFile = function(){return new Promise((resolve) => {
  var self = this;
  var salt = crypto.randomBytes(32);
  var iv   = crypto.randomBytes(16);
  var scryptKey = scrypt(self.userPassword, salt, 8192, 8, 1, 32);

  var cipher     = crypto.createCipheriv("aes-128-ctr", scryptKey.slice(0, 16), iv);
  var first      = cipher.update(self.privateKeyBuffer);
  var final      = cipher.final();
  var ciphertext = Buffer.concat([first, final]);

  var sliced = scryptKey.slice(16, 32);
  sliced = new Buffer(sliced, "hex");
  var mac = ethUtil.sha3(Buffer.concat([ scryptKey.slice(16, 32), Buffer.from(ciphertext, "hex") ]))

  var hexCiphertext = ciphertext.toString("hex");
  var hexIv         = Buffer.from(iv).toString("hex");
  var hexSalt       = Buffer.from(salt).toString("hex");
  var hexMac        = Buffer.from(mac).toString("hex");

  var keystoreFile = {
    "version": 3,
    "id"     : uuidv4({ random: crypto.randomBytes(16) }),
    "address": self.ethAddress.slice(-40),
    "crypto" : {
      "ciphertext": hexCiphertext,
      "cipherparams": {
        "iv": hexIv
      },
      "cipher": "aes-128-ctr",
      "kdf": "scrypt",
      "kdfparams": {
        "dklen": 32,
        "salt" : hexSalt,
        "n"    : 8192,
        "r"    : 8,
        "p"    : 1
      },
      "mac": hexMac
    }
  };

  fs.writeFileSync("wallets/wallet.json", JSON.stringify(keystoreFile, null, 2)+"\n");

  resolve();
})}

EthWallet.prototype.Display = function(){
  console.log("Private Key:", this.privateKeyString);
  console.log("Public Key :", this.publicKeyString);
  console.log("SHA-3 Hash :", this.sha3Hash);
  console.log("Address    :", this.ethAddress);
  console.log();
}

var ethWallet = new EthWallet();

ethWallet.PromptUserForPassword()
.then(() => ethWallet.GetPrivateKey())
.then(() => ethWallet.GetPublicKey())
.then(() => ethWallet.GetEthAddress())
.then(() => ethWallet.GetQrCodes())
.then(() => ethWallet.GetIdenticon())
.then(() => ethWallet.GetKeystoreFile())
.then(() => ethWallet.Display());
