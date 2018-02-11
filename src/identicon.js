const pngjs      = require("pngjs");
const parseColor = require("parse-color");

function Identicon(){
  this.randseed = new Array(4);
}

Identicon.prototype.SeedRand = function(seed){
  var self = this;

  for(var i = 0; i < self.randseed.length; i++)
    self.randseed[i] = 0;

  for(var i = 0; i < seed.length; i++)
    self.randseed[i % 4] = (self.randseed[i % 4] << 5) - self.randseed[i % 4] + seed.charCodeAt(i);
}

Identicon.prototype.Rand = function(seed){
  var self = this;
  var t = self.randseed[0] ^ (self.randseed[0] << 11);

  self.randseed[0] = self.randseed[1];
  self.randseed[1] = self.randseed[2];
  self.randseed[2] = self.randseed[3];
  self.randseed[3] = self.randseed[3] ^ (self.randseed[3] >> 19) ^ t ^ (t >> 8);

  return(self.randseed[3] >>> 0) / ((1 << 31) >>> 0);
}

Identicon.prototype.CreateColor = function(seed){
  var self = this;

  var h = Math.floor(self.Rand() * 360);
  var s = self.Rand() * 60 + 40 + "%";
  var l = (self.Rand() + self.Rand() + self.Rand() + self.Rand()) * 25 + "%";

  return `hsl(${h},${s},${l})`;
}

Identicon.prototype.CreateImageData = function(size){
  var self = this;
  var width = size;
  var height = size;
  var dataWidth = Math.ceil(width / 2);
  var mirrorWidth = width - dataWidth;
  var data = [];

  for(var y = 0; y < height; y++){
    var row = [];

    for(var x = 0; x < dataWidth; x++)
      row[x] = Math.floor(self.Rand() * 2.3);

    var r = row.slice(0, mirrorWidth).reverse();
    row = row.concat(r);

    for(var i = 0; i < row.length; i++)
      data.push(row[i]);
  }

  return data;
}

Identicon.prototype.BuildOpts = function(address){
  var self = this;

  var newOpts   = {};
  newOpts.size  =  8;
  newOpts.scale = 25;
  newOpts.seed  = address;

  self.SeedRand(newOpts.seed);

  newOpts.color     = self.CreateColor();
  newOpts.bgcolor   = self.CreateColor();
  newOpts.spotcolor = self.CreateColor();

  return newOpts;
}

Identicon.prototype.CreateIcon = function(address){
  var self = this;
  var opts = self.BuildOpts(address);
  var imageData = self.CreateImageData(opts.size);
  var width = Math.sqrt(imageData.length);

  var bgColor   = parseColor(opts.bgcolor).rgb;
  var fgColor   = parseColor(opts.color).rgb;
  var spotColor = parseColor(opts.spotcolor).rgb;

  var imageWidth = opts.size * opts.scale;

  var png = new pngjs.PNG({
    width: imageWidth,
    height: imageWidth,
    colorType: 2
  });

  for(var i = 0; i < imageData.length; i++){
    var row = Math.floor(i / width);
    var col = i % width;
    var idx = (row * opts.size * opts.scale + col) * opts.scale * 4;
    var color;

    switch(imageData[i]){
      case 0:
        color = bgColor;
        break;
      case 1:
        color = fgColor;
        break;
      default:
        color = spotColor;
    }

    for(var y = 0; y < opts.scale; y++){
      for(var x = 0; x < opts.scale; x++){
        var o = idx + (x + y * opts.size * opts.scale) * 4;
        png.data[o] = color[0];
        png.data[o + 1] = color[1];
        png.data[o + 2] = color[2];
        png.data[o + 3] = 255;
      }
    }
  }

  return pngjs.PNG.sync.write(png, {});
}

module.exports = new Identicon;
