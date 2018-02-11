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
  this.walletCurrent    = 1;
  this.walletMax        = 1;
  this.lock             = false;
  this.generator        = elliptic.ec("secp256k1").g;

  if(!fs.existsSync("./wallets"))fs.mkdirSync("./wallets");
}

EthWallet.prototype.Menu = function(){return new Promise((resolve) => {
  var self = this;
  process.stdout.write("\033c");
  console.log("========== Menu ==========");
  console.log("1) Generate a single wallet");
  console.log("2) Generate multiple wallets");
  console.log("3) Get data from private key");
  console.log("4) Quit");
  console.log("");

  var rl = readline.createInterface({
    "input" : process.stdin,
    "output": process.stdout
  });

  rl.question("Select an option: ", (answer) => {
    if(answer == 1){
      rl.close();
      self.walletCurrent = 1;
      self.walletMax = 1;
      self.PromptUserForPassword()
      .then(() => self.GenerateWallet());
      resolve();
    }
    else if(answer == 2){
      rl.close();
      self.PromptUserForPassword()
      .then(() => self.GenerateMultipleWallets());
      resolve();
    }
    else if(answer == 3){
      rl.close();
      self.GetDataFromPrivateKey()
      resolve();
    }
    else{
      rl.close();
      self.Menu();
      resolve();
    }
  });
})}

EthWallet.prototype.GetDataFromPrivateKey = function(){return new Promise((resolve) => {
  var self = this;

  var rl = readline.createInterface({
    "input" : process.stdin,
    "output": process.stdout
  });

  rl.question("Type in a 64-character hexadecimal string and hit enter\n", (answer) => {
    rl.close();

    var buffHex = new Buffer(answer, "hex");
    self.privateKeyBuffer = buffHex;
    self.privateKeyString = self.privateKeyBuffer.toString("hex");

    self.PromptUserForPassword()
    .then(() => self.GetPublicKey())
    .then(() => self.GetEthAddress())
    .then(() => self.GetQrCodes())
    .then(() => self.GetIdenticon())
    .then(() => self.GetKeystoreFile())
    .then(() => {
      console.log(`Wallets generated: ${self.walletCurrent}/${self.walletMax}`);
      resolve();
    });
  });
})}

EthWallet.prototype.PromptUserForPassword = function(){return new Promise((resolve) => {
  var self = this;

  var rl = readline.createInterface({
    "input" : process.stdin,
    "output": process.stdout
  });

  rl.question("Enter a password to encrypt your private key: ", (answer) => {
    rl.close();
    self.userPassword = answer;
    resolve();
  });
})}

EthWallet.prototype.GenerateMultipleWallets = function(){return new Promise((resolve) => {
  var self = this;

  var rl = readline.createInterface({
    "input" : process.stdin,
    "output": process.stdout
  });

  rl.question("Enter the number of wallets you want to generate: ", (answer) => {
    answer = String(answer).replace(/^\s+|\s+$/g, "");
    if(!isNaN(answer) && answer != ""){
      rl.close();
      self.walletCurrent = 1;
      self.walletMax = parseInt(answer, 10);
      self.GenerateWallet();
      resolve();
    }else{
      rl.close();
      self.GenerateMultipleWallets();
      resolve();
    }
  });
})}

EthWallet.prototype.GenerateWallet = function(){return new Promise((resolve) => {
  var self = this;

  self.GetPrivateKey()
  .then(() => self.GetPublicKey())
  .then(() => self.GetEthAddress())
  .then(() => self.GetQrCodes())
  .then(() => self.GetIdenticon())
  .then(() => self.GetKeystoreFile())
  .then(() => {
    console.log(`Wallets generated: ${self.walletCurrent}/${self.walletMax}`);
    if(self.walletCurrent++ < self.walletMax)
      self.GenerateWallet();
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

  qrPrivateKey.pipe(fs.createWriteStream(`wallets/private-key-${self.walletCurrent}.png`));
  qrEthAddress.pipe(fs.createWriteStream(`wallets/eth-address-${self.walletCurrent}.png`));

  resolve();
})}

EthWallet.prototype.GetIdenticon = function(){return new Promise((resolve) => {
  var self = this;
  var icon = identicon.CreateIcon(self.ethAddress);

  fs.writeFileSync(`wallets/identicon-${self.walletCurrent}.png`, icon);

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

  var data = `ETH Address: ${self.ethAddress}\n`;
  data    += `Private Key: ${self.privateKeyString}\n`;

  fs.writeFileSync(`wallets/wallet-${self.walletCurrent}.json`, JSON.stringify(keystoreFile, null, 2)+"\n");
  fs.writeFileSync(`wallets/data-${self.walletCurrent}.txt`, data);

  resolve();
})}

EthWallet.prototype.Display = function(){return new Promise((resolve) => {
  console.log("Private Key:", this.privateKeyString);
  console.log("Public Key :", this.publicKeyString);
  console.log("SHA-3 Hash :", this.sha3Hash);
  console.log("Address    :", this.ethAddress);
  console.log();
  resolve();
})}

var ethWallet = new EthWallet();
ethWallet.Menu();
