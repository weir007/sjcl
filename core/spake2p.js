/** @fileOverview Javascript SPAKE2+ implementation.
 * Based on EC group - edwards25519 Curve
 * @author weir007
 */


/**
 * @constructor
 * @param {curve} curve=sjcl.ecc.curves.c25519
 * @param {object} hash=sjcl.hash.sha256
 */
sjcl.keyexchange.spake2p = function(curve, hash) {
  this.default_kdf_iter = 10;

  this.curve = curve || sjcl.ecc.curves.c25519;
  this.hash = hash || sjcl.hash.sha256;
  this.hmac = function(_key, _hash) {
	return new sjcl.misc.hmac(_key, _hash || this.hash);
  };
  this.kdf = function(password, salt, count, len) {
    return sjcl.misc.pbkdf2(password, salt, count, len, this.hmac);
  };

  this._curveBitLength = this.curve.r.bitLength();
	/* Generate M and N */
	/*
	var _seedM = this.curve.oid+' point generation seed (M)', _seedN = this.curve.oid+' point generation seed (N)';
	
	var bits = 0, blockM = [], blockN = [];
	while (bits < this._curveBitLength)
	{
		_seedM = this.hash(_seedM);
		_seedN = this.hash(_seedN);
		blockM = blockM.concat(_seedM);
		blockN = blockM.concat(_seedN);
	}
	this.M = sjcl.bitArray.clamp(blockM, this._curveBitLength);
	this.N = sjcl.bitArray.clamp(blockN, this._curveBitLength);
	*/
  var _M = "0xd048032c6ea0b6d697ddc2e86bda85a33adac920f1bf18e1b0c6d166a5cecdaf",
  _N = "0xd3bfb518f44f3430f29d0c92af503865a1ed3281dc69b35dd868ba85f886c4ab";
  /* decode */
  this.M = this.curve.decode(_M);
  this.N = this.curve.decode(_N);
};
  
/**
 * @param {string} P The password
 * @param {bitArray} s The salt for KDF
 * @param {number} c The iteration count for KDF
 * @return [bn w0, bn w1] = PBKDF(P)
 */
sjcl.keyexchange.spake2p.prototype._makeW = function(P, s, c) {
	var w = this.kdf(P, s||'salt', c || this.default_kdf_iter, this._curveBitLength*2);

	w = [
		  new this.curve.field(sjcl.bn.fromBits(sjcl.bitArray.bitSlice(w,0,this._curveBitLength))),
		  new this.curve.field(sjcl.bn.fromBits(sjcl.bitArray.bitSlice(w,this._curveBitLength,this._curveBitLength*2)))
		];
	return w;
};

/**
 * @param {String} I The username.
 * @param {String} P The password.
 * @return {bitArray} verifier L
 * @return verifier tuples
 */
sjcl.keyexchange.spake2p.prototype.makeVerifier =  function(I, P, M, N) {
  M = M || this.M;
  N = N || this.N;
  var w = this._makeW(P);
  var L = this.curve.G.mult(w[1]);
  var w0M = M.mult(w[0]);
  var w0N = N.mult(w[0]);
  return {w0:w[0].toString(),
	w0M:this.curve.encode(w0M),
	w0N:this.curve.encode(w0N),
    L:this.curve.encode(L)
  };
};

/**
 * @param {String} P The password.
 * @param {object} w The output of function _makeW.
 * @param {object} M
 * @return {bitArray} verifier L
 * @return {object} pA {bn x, string X}
 */
sjcl.keyexchange.spake2p.prototype.getPA = function(I, P, M, paranoia) {
  var w = this._makeW(I, P);
  var x = sjcl.bn.random(this.curve.r, paranoia||6);
  var X = this.curve.G.mult2(x, w[0], M || this.M);
  return {x:x, X:this.curve.encode(X)};
};

/**
 * @param {String} I The username.
 * @param {string} Y EC point from server side
 * @param {object} w The output of function _makeW.
 * @param {object} pA The output of function getPA
 * @return {bitArray} session key SK = H(TT)
 * TT = A.B.X.Y.Z.V.w0
 */
sjcl.keyexchange.spake2p.prototype.getSK = function(I, P, Y, pA, N) {
  var h = this.curve.cofactor, TT = I+':spake2+_server', w = this._makeW(I, P);
  var pY = this.curve.decode(Y);
  var hx = h.mul(pA.x), hw1 = w[1].mul(h);
  var hxw0 = new this.curve.field(0).sub(hx.mul(w[0])),
  	  hw1w0 = new this.curve.field(0).sub(hw1.mul(w[0]));

  N = N || this.N;
  var Z = pY.mult2(hx, hxw0, N),
  	V = pY.mult2(hw1, hw1w0, N);
  	
  TT = sjcl.codec.bytes.toBits(TT.split(''));
  var X = sjcl.codec.hex.toBits(pA.X);
  Y = sjcl.codec.hex.toBits(Y);
  var Z = sjcl.codec.hex.toBits(this.curve.encode(Z)),
  V = sjcl.codec.hex.toBits(this.curve.encode(V));
  
  TT = TT.concat(X).concat(Y).concat(Z).concat(V).concat(w[0].toBits());
  return this.hash.hash(TT);
};
  
/**
 * @param {string} I The username
 * @return {bitArray} SK Session key
 */
sjcl.keyexchange.spake2p.prototype.getKC = function(I, SK) {
  var bitLength = sjcl.bitArray.bitLength(SK);
  return this.kdf(sjcl.bitArray.bitSlice(SK, 0, bitLength/2), I, this.default_kdf_iter, bitLength);
};

/**
 * @param {bitArray} Kc The output of function getKC
 * @param {bitArray} KcB
 * @return {boolean} 
 */
sjcl.keyexchange.spake2p.prototype.confirmSK = function(Kc, KcA, KcB) {
	//return Kc.bitSlice(-KcB.bitLength()).equals(KcB);
	return sjcl.bitArray.equal(Kc, KcA.concat(KcB));
};
