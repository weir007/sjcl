/**
 * base class for all ecc operations.
 * @namespace
 */
sjcl.ecc = {};

/**
 * Represents a point on a curve in affine coordinates.
 * @constructor
 * @param {sjcl.ecc.curve} curve The curve that this point lies on.
 * @param {bigInt} x The x coordinate.
 * @param {bigInt} y The y coordinate.
 */
sjcl.ecc.point = function(curve,x,y) {
  if (x === undefined) {
    this.isIdentity = true;
	this.x = new curve.field(0);
	this.y = new curve.field(1);
  } else {
    if (x instanceof sjcl.bn) {
      x = new curve.field(x);
    }
    if (y instanceof sjcl.bn) {
      y = new curve.field(y);
    }

    this.x = x;
    this.y = y;

    this.isIdentity = false;
  }
  this.curve = curve;
};



sjcl.ecc.point.prototype = {
  toJac: function() {
    return this.curve.twisted === true ? this.toExt() : new sjcl.ecc.pointJac(this.curve, this.x, this.y, new this.curve.field(1));
  },
  
  toExt: function() {
	return new sjcl.ecc.pointExt(this.curve, this.x, this.y, new this.curve.field(1), this.x.mul(this.y));
  },

  mult: function(k) {
    return this.toJac().mult(k, this).toAffine();
  },

  /**
   * Multiply this point by k, added to affine2*k2, and return the answer in Jacobian coordinates.
   * @param {bigInt} k The coefficient to multiply this by.
   * @param {bigInt} k2 The coefficient to multiply affine2 this by.
   * @param {sjcl.ecc.point} affine The other point in affine coordinates.
   * @return {sjcl.ecc.pointJac} The result of the multiplication and addition, in Jacobian coordinates.
   */
  mult2: function(k, k2, affine2) {
    return this.toJac().mult2(k, this, k2, affine2).toAffine();
  },
  /* precompute with 4-bit fixed window */
  multiples: function() {
    var m, i, j;
    if (this._multiples === undefined) {
      j = this.toJac().doubl();
      m = [j];
      for (i=3; i<16; i++) {
        j = j.add(this);
        m.push(j);
      }
      this._multiples = [new sjcl.ecc.point(this.curve), this].concat(sjcl.ecc.pointJac.toAffineMultiple(m));
    }
    return this._multiples;
  },

  negate: function() {
    var newY = new this.curve.field(0).sub(this.y).normalize().reduce();
    return new sjcl.ecc.point(this.curve, this.x, newY);
  },

  isValid: function() {
	if (this.curve.twisted)
	  return this.curve.b.mul(this.x).mul(this.y).square().add(1).equals(this.x.square().mul(this.curve.a).add(this.y.square()));
	else
      return this.y.square().equals(this.curve.b.add(this.x.mul(this.curve.a.add(this.x.square()))));
  },

  toBits: function() {
    return sjcl.bitArray.concat(this.x.toBits(), this.y.toBits());
  }
};

/**
 * Represents a point on a curve in Jacobian coordinates. Coordinates can be specified as bigInts or strings (which
 * will be converted to bigInts).
 *
 * @constructor
 * @param {bigInt/string} x The x coordinate.
 * @param {bigInt/string} y The y coordinate.
 * @param {bigInt/string} z The z coordinate.
 * @param {sjcl.ecc.curve} curve The curve that this point lies on.
 */
sjcl.ecc.pointJac = function(curve, x, y, z) {
  if (x === undefined) {
    this.isIdentity = true;
  } else {
    this.x = x;
    this.y = y;
    this.z = z;
    this.isIdentity = false;
  }
  this.curve = curve;
};

/**
 * Returns points converted to affine coordinates.
 * @param {Array} points An array of {sjcl.ecc.pointJac} to convert.
 * @return {Array} An array of {sjcl.ecc.point} that were converted.
 */
sjcl.ecc.pointJac.toAffineMultiple = function (points) {
  var i=0, j, ret = new Array(points.length), p, tmp, z, zi, zi2, curve;
  for (; i<points.length; i++) {
    p = points[i];
    if (curve != p.curve) {
      // if not first time
      if (curve) {
        // curve mismatch so just convert points individually
        for (i=0; i<points.length; i++) {
          ret[i] = points[i].toAffine();
        }
        return ret;
      } else {
        curve = p.curve;
      }
    }
    // multiply all z coordinates
    if (!p.isIdentity && !p.z.equals(0)) {
      if (tmp) {
        tmp.push(z);
        z = z.mul(p.z);
      } else {
        z = p.z;
        tmp = [];
      }
    }
  }
  // if any z coordinates invert
  if (tmp) {
    // z is now the product of all z coordinates inverted
    z = z.inverse();
    j = tmp.length-1;
  }
  for (i--; i>=0; i--) {
    p = points[i];
    if (p.isIdentity || p.z.equals(0)) {
      ret[i] = new sjcl.ecc.point(p.curve);
    } else {
      // if not last
      if (j >= 0) {
        // remove all other inverted z coordinates from product of inverses
        // zi is now inverse of p.z
        zi = z.mul(tmp[j]);
        // remove the inverse of p.z from product of inverses
        z = z.mul(p.z);
        j--;
      } else {
        zi = z;
      }
	  /* weir007 */
	  if (curve.twisted) ret[i] = new sjcl.ecc.point(p.curve, p.x.mul(zi).fullReduce(), p.y.mul(zi).fullReduce());
      else {
		zi2 = zi.square();
	  ret[i] = new sjcl.ecc.point(p.curve, p.x.mul(zi2).fullReduce(), p.y.mul(zi2.mul(zi)).fullReduce());
	  }
    }
  }
  return ret;
};

sjcl.ecc.pointJac.prototype = {
  /**
   * Adds S and T and returns the result in Jacobian coordinates. Note that S must be in Jacobian coordinates and T must be in affine coordinates.
   * @param {sjcl.ecc.pointJac} S One of the points to add, in Jacobian coordinates.
   * @param {sjcl.ecc.point} T The other point to add, in affine coordinates.
   * @return {sjcl.ecc.pointJac} The sum of the two points, in Jacobian coordinates.
   */
  add: function(T) {
    var S = this, sz2, c, d, c2, x1, x2, x, y1, y2, y, z;
    if (S.curve !== T.curve) {
      throw new sjcl.exception.invalid("sjcl.ecc.add(): Points must be on the same curve to add them!");
    }

    if (S.isIdentity) {
      return T.toJac();
    } else if (T.isIdentity) {
      return S;
    }

    sz2 = S.z.square();
    c = T.x.mul(sz2).subM(S.x);

    if (c.equals(0)) {
      if (S.y.equals(T.y.mul(sz2.mul(S.z)))) {
        // same point
        return S.doubl();
      } else {
        // inverses
        return new sjcl.ecc.pointJac(S.curve);
      }
    }

    d = T.y.mul(sz2.mul(S.z)).subM(S.y);
    c2 = c.square();

    x1 = d.square();
    x2 = c.square().mul(c).addM( S.x.add(S.x).mul(c2) );
    x  = x1.subM(x2);

    y1 = S.x.mul(c2).subM(x).mul(d);
    y2 = S.y.mul(c.square().mul(c));
    y  = y1.subM(y2);

    z  = S.z.mul(c);

    return new sjcl.ecc.pointJac(this.curve,x,y,z);
  },

  /**
   * doubles this point.
   * @return {sjcl.ecc.pointJac} The doubled point.
   */
  doubl: function() {
    if (this.isIdentity) { return this; }

    var
      y2 = this.y.square(),
      a  = y2.mul(this.x.mul(4)),
      b  = y2.square().mul(8),
      z2 = this.z.square(),
      c  = this.curve.a.toString() == (new sjcl.bn(-3)).toString() ?
                this.x.sub(z2).mul(3).mul(this.x.add(z2)) :
                this.x.square().mul(3).add(z2.square().mul(this.curve.a)),
      x  = c.square().subM(a).subM(a),
      y  = a.sub(x).mul(c).subM(b),
      z  = this.y.add(this.y).mul(this.z);
    return new sjcl.ecc.pointJac(this.curve, x, y, z);
  },

  /**
   * Returns a copy of this point converted to affine coordinates.
   * @return {sjcl.ecc.point} The converted point.
   */
  toAffine: function() {
    if (this.isIdentity || this.z.equals(0)) {
      return new sjcl.ecc.point(this.curve);
    }
    var zi = this.z.inverse(), zi2 = zi.square();
    return new sjcl.ecc.point(this.curve, this.x.mul(zi2).fullReduce(), this.y.mul(zi2.mul(zi)).fullReduce());
  },

  /**
   * Multiply this point by k and return the answer in Jacobian coordinates.
   * @param {bigInt} k The coefficient to multiply by.
   * @param {sjcl.ecc.point} affine This point in affine coordinates.
   * @return {sjcl.ecc.pointJac} The result of the multiplication, in Jacobian coordinates.
   */
  mult: function(k, affine) {
    if (typeof(k) === "number") {
      k = [k];
    } else if (k.limbs !== undefined) {
      k = k.normalize().limbs;
    }

    var i, j, out = new sjcl.ecc.point(this.curve).toJac(), multiples = affine.multiples();

    for (i=k.length-1; i>=0; i--) {
      for (j=sjcl.bn.prototype.radix-4; j>=0; j-=4) {
        out = out.doubl().doubl().doubl().doubl().add(multiples[k[i]>>j & 0xF]);
      }
    }

    return out;
  },

  /**
   * Multiply this point by k, added to affine2*k2, and return the answer in Jacobian coordinates.
   * @param {bigInt} k The coefficient to multiply this by.
   * @param {sjcl.ecc.point} affine This point in affine coordinates.
   * @param {bigInt} k2 The coefficient to multiply affine2 this by.
   * @param {sjcl.ecc.point} affine The other point in affine coordinates.
   * @return {sjcl.ecc.pointJac} The result of the multiplication and addition, in Jacobian coordinates.
   */
  mult2: function(k1, affine, k2, affine2) {
    if (typeof(k1) === "number") {
      k1 = [k1];
    } else if (k1.limbs !== undefined) {
      k1 = k1.normalize().limbs;
    }

    if (typeof(k2) === "number") {
      k2 = [k2];
    } else if (k2.limbs !== undefined) {
      k2 = k2.normalize().limbs;
    }

    var i, j, out = new sjcl.ecc.point(this.curve).toJac(), m1 = affine.multiples(),
        m2 = affine2.multiples(), l1, l2;

    for (i=Math.max(k1.length,k2.length)-1; i>=0; i--) {
      l1 = k1[i] | 0;
      l2 = k2[i] | 0;
      for (j=sjcl.bn.prototype.radix-4; j>=0; j-=4) {
        out = out.doubl().doubl().doubl().doubl().add(m1[l1>>j & 0xF]).add(m2[l2>>j & 0xF]);
      }
    }

    return out;
  },

  negate: function() {
    return this.toAffine().negate().toJac();
  },

  isValid: function() {
    var z2 = this.z.square(), z4 = z2.square(), z6 = z4.mul(z2);
    return this.y.square().equals(
             this.curve.b.mul(z6).add(this.x.mul(
               this.curve.a.mul(z4).add(this.x.square()))));
  }
};

/* weir007 added extended coordinates for Twisted Edwards Curves */
sjcl.ecc.pointExt = function(curve, x, y, z, t) {
  if (x === undefined) {
    this.isIdentity = true;
  } else {
    this.x = x;
    this.y = y;
    this.z = z;
    this.t = t;
    this.isIdentity = false;
  }
  this.curve = curve;
};

sjcl.ecc.pointExt.toAffineMultiple = function (points) {
  var i=0, j, ret = new Array(points.length), p, tmp, z, zi, zi2, curve;
  for (; i<points.length; i++) {
    p = points[i];
    if (curve != p.curve) {
      // if not first time
      if (curve) {
        // curve mismatch so just convert points individually
        for (i=0; i<points.length; i++) {
          ret[i] = points[i].toAffine();
        }
        return ret;
      } else {
        curve = p.curve;
      }
    }
    // multiply all z coordinates
    if (!p.isIdentity && !p.z.equals(0)) {
      if (tmp) {
        tmp.push(z);
        z = z.mul(p.z);
      } else {
        z = p.z;
        tmp = [];
      }
    }
  }
  // if any z coordinates invert
  if (tmp) {
    // z is now the product of all z coordinates inverted
    z = z.inverse();
    j = tmp.length-1;
  }
  for (i--; i>=0; i--) {
    p = points[i];
    if (p.isIdentity || p.z.equals(0)) {
      ret[i] = new sjcl.ecc.point(p.curve);
    } else {
      // if not last
      if (j >= 0) {
        // remove all other inverted z coordinates from product of inverses
        // zi is now inverse of p.z
        zi = z.mul(tmp[j]);
        // remove the inverse of p.z from product of inverses
        z = z.mul(p.z);
        j--;
      } else {
        zi = z;
      }
      ret[i] = new sjcl.ecc.point(p.curve, p.x.mul(zi).fullReduce(), p.y.mul(zi).fullReduce());
    }
  }
  return ret;
};

sjcl.ecc.pointExt.prototype = {
  add: function(Q) {	
	var P = this, A, B, C, D, E, F, G, H, T2, x, y, z, t;
	if (P.curve !== Q.curve) {
	  throw new sjcl.exception.invalid("sjcl.ecc.add(): Points must be on the same curve to add them!");
	}
	
	if (P.isIdentity) {
	  return Q.toExt();
	} else if (Q.isIdentity) {
	  return P;
	}
	/* madd-2008-hwcd */
	/* A = X1*X2 */
	A = P.x.mul(Q.x);
    /* B = Y1*Y2 */
	B = P.y.mul(Q.y);
    /* C = T1*d*T2 */
	C = P.t.mul(this.curve.b).mul(Q.x).mul(Q.y);
    /* D = Z1 */
	D = P.z.copy();
    /* E = (X1+Y1)*(X2+Y2)-A-B */
	E = P.x.add(P.y).mul(Q.x.add(Q.y)).sub(A).sub(B);
    /* F = D-C */
	F = D.sub(C);
    /* G = D+C */
	G = D.add(C);
    /* H = B-a*A */
	H = B.sub(A.mul(this.curve.a));
    /* X3 = E*F */
	x = E.mul(F);
    /* Y3 = G*H */
	y = G.mul(H);
    /* T3 = E*H */
	t = E.mul(H);
    /* Z3 = F*G */
	z = F.mul(G);
	
	/* madd-2008-hwcd-4 TBD: add-2008-hwcd-3 * /
	
	/* A = (Y1-X1)*(Y2+X2) * /
	A = (P.y.sub(P.x)).mul(Q.y.add(Q.x));
	/* B = (Y1+X1)*(Y2-X2) * /
	B = (P.y.add(P.x)).mul(Q.y.sub(Q.x));
	/* C = Z1*2*T2 = Z1*2*X2*Y2 * /
	C = P.z.mul(2).mul(Q.x).mul(Q.y);
	/* D = 2*T1 * /
	D = P.t.mul(2);
	/* E = D+C * /
	E = D.add(C);
	/* F = B-A * /
	F = B.sub(A);
	/* G = B+A * /
	G = B.add(A);
	/* H = D-C * /
	H = D.sub(C);
	/* X3 = E*F * /
	x = E.mul(F);
	/* Y3 = G*H * /
	y = G.mul(H);
	/* T3 = E*H * /
	t = E.mul(H);
	/* Z3 = F*G * /
	z = F.mul(G);
	*/
	return new sjcl.ecc.pointExt(this.curve,x,y,z,t);
  },
  
  doubl: function() {
	if (this.isIdentity) { return this; }
	/* dbl-2008-hwcd */
	var A = this.x.square(),
	B = this.y.square(),
	C = this.z.square().mul(2),
	D = this.curve.a.mul(A),
	E = this.x.add(this.y).square().sub(A).sub(B),
	G = D.add(B),
	F = G.sub(C),
	H = D.sub(B),
	x = E.mul(F),
	y = G.mul(H),
	t = E.mul(H),
	z = F.mul(G);
	return new sjcl.ecc.pointExt(this.curve, x, y, z, t);
  },
  
  toAffine: function() {
	if (this.isIdentity || this.z.equals(0)) {
	  return new sjcl.ecc.point(this.curve);
	}
	var zi = this.z.inverse();
	return new sjcl.ecc.point(this.curve, this.x.mul(zi).fullReduce(), this.y.mul(zi).fullReduce());
  },
  
  mult: function(k, affine) {
	if (typeof(k) === "number") {
	  k = [k];
	} else if (k.limbs !== undefined) {
	  k = k.normalize().limbs;
	}
	
	var i, j, out = new sjcl.ecc.point(this.curve).toExt(), multiples = affine.multiples();

    for (i=k.length-1; i>=0; i--) {
      for (j=sjcl.bn.prototype.radix-4; j>=0; j-=4) {
        out = out.doubl().doubl().doubl().doubl().add(multiples[k[i]>>j & 0xF]);
      }
    }

    return out;
  },
  
  mult2: function(k1, affine, k2, affine2) {
    if (typeof(k1) === "number") {
      k1 = [k1];
    } else if (k1.limbs !== undefined) {
      k1 = k1.normalize().limbs;
    }

    if (typeof(k2) === "number") {
      k2 = [k2];
    } else if (k2.limbs !== undefined) {
      k2 = k2.normalize().limbs;
    }

    var i, j, out = new sjcl.ecc.point(this.curve).toExt(), m1 = affine.multiples(),
        m2 = affine2.multiples(), l1, l2;

    for (i=Math.max(k1.length,k2.length)-1; i>=0; i--) {
      l1 = k1[i] | 0;
      l2 = k2[i] | 0;
      for (j=sjcl.bn.prototype.radix-4; j>=0; j-=4) {
        out = out.doubl().doubl().doubl().doubl().add(m1[l1>>j & 0xF]).add(m2[l2>>j & 0xF]);
      }
    }

    return out;
  },

  negate: function() {
    return this.toAffine().negate().toExt();
  },

  isValid: function() {
    var x2 = this.x.square(), y2 = this.y.square(), z2 = this.z.square(), t2 = this.t.square();
    return this.curve.a.mul(x2).add(y2).equals(this.curve.b.mul(t2).add(z2));
  }
};

/**
 * Construct an elliptic curve. Most users will not use this and instead start with one of the NIST curves defined below.
 *
 * @constructor
 * @param {bigInt} p The prime modulus.
 * @param {bigInt} r The prime order of the curve.
 * @param {bigInt} a The constant a in the equation of the curve y^2 = x^3 + ax + b (for NIST curves, a is always -3).
 * @param {bigInt} x The x coordinate of a base point of the curve.
 * @param {bigInt} y The y coordinate of a base point of the curve.
 */
sjcl.ecc.curve = function(Field, r, a, b, x, y, cofactor, oid, twisted) {
  this.field = Field;
  this.r = new sjcl.bn(r);
  this.a = new Field(a);
  this.b = new Field(b);
  this.G = new sjcl.ecc.point(this, new Field(x), new Field(y));
  this.cofactor = new Field(cofactor || 1);
  this.oid = oid || 'unknown oid';
  this.twisted = twisted || false;
};

sjcl.ecc.curve.prototype.fromBits = function (bits) {
  var w = sjcl.bitArray, l = this.field.prototype.exponent + 7 & -8,
      p = new sjcl.ecc.point(this, this.field.fromBits(w.bitSlice(bits, 0, l)),
                             this.field.fromBits(w.bitSlice(bits, l, 2*l)));
  if (!p.isValid()) {
    throw new sjcl.exception.corrupt("not on the curve!");
  }
  return p;
};

sjcl.ecc.curves = {
  c192: new sjcl.ecc.curve(
    sjcl.bn.prime.p192,
    "0xffffffffffffffffffffffff99def836146bc9b1b4d22831",
    -3,
    "0x64210519e59c80e70fa7e9ab72243049feb8deecc146b9b1",
    "0x188da80eb03090f67cbf20eb43a18800f4ff0afd82ff1012",
    "0x07192b95ffc8da78631011ed6b24cdd573f977a11e794811",
	"1.2.840.10045.3.1.1"),

  c224: new sjcl.ecc.curve(
    sjcl.bn.prime.p224,
    "0xffffffffffffffffffffffffffff16a2e0b8f03e13dd29455c5c2a3d",
    -3,
    "0xb4050a850c04b3abf54132565044b0b7d7bfd8ba270b39432355ffb4",
    "0xb70e0cbd6bb4bf7f321390b94a03c1d356c21122343280d6115c1d21",
    "0xbd376388b5f723fb4c22dfe6cd4375a05a07476444d5819985007e34",
	"1.3.132.0.33"),

  c256: new sjcl.ecc.curve(
    sjcl.bn.prime.p256,
	"0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551",
    -3,
    "0x5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b",
    "0x6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296",
    "0x4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5",
	"1.2.840.10045.3.1.7"),

  c384: new sjcl.ecc.curve(
    sjcl.bn.prime.p384,
    "0xffffffffffffffffffffffffffffffffffffffffffffffffc7634d81f4372ddf581a0db248b0a77aecec196accc52973",
    -3,
    "0xb3312fa7e23ee7e4988e056be3f82d19181d9c6efe8141120314088f5013875ac656398d8a2ed19d2a85c8edd3ec2aef",
    "0xaa87ca22be8b05378eb1c71ef320ad746e1d3b628ba79b9859f741e082542a385502f25dbf55296c3a545e3872760ab7",
    "0x3617de4a96262c6f5d9e98bf9292dc29f8f41dbd289a147ce9da3113b5f0b8c00a60b1ce1d7e819d7a431d7c90ea0e5f",
	"1.3.132.0.34"),
    
  c521: new sjcl.ecc.curve(
    sjcl.bn.prime.p521,
    "0x1FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFA51868783BF2F966B7FCC0148F709A5D03BB5C9B8899C47AEBB6FB71E91386409",
    -3,
    "0x051953EB9618E1C9A1F929A21A0B68540EEA2DA725B99B315F3B8B489918EF109E156193951EC7E937B1652C0BD3BB1BF073573DF883D2C34F1EF451FD46B503F00",
    "0xC6858E06B70404E9CD9E3ECB662395B4429C648139053FB521F828AF606B4D3DBAA14B5E77EFE75928FE1DC127A2FFA8DE3348B3C1856A429BF97E7E31C2E5BD66",
    "0x11839296A789A3BC0045C8A5FB42C7D1BD998F54449579B446817AFBD17273E662C97EE72995EF42640C550B9013FAD0761353C7086A272C24088BE94769FD16650",
	"1.3.132.0.35"),

  k192: new sjcl.ecc.curve(
    sjcl.bn.prime.p192k,
    "0xfffffffffffffffffffffffe26f2fc170f69466a74defd8d",
    0,
    3,
    "0xdb4ff10ec057e9ae26b07d0280b7f4341da5d1b1eae06c7d",
    "0x9b2f2f6d9c5628a7844163d015be86344082aa88d95e2f9d"),

  k224: new sjcl.ecc.curve(
    sjcl.bn.prime.p224k,
    "0x010000000000000000000000000001dce8d2ec6184caf0a971769fb1f7",
    0,
    5,
    "0xa1455b334df099df30fc28a169a467e9e47075a90f7e650eb6b7a45c",
    "0x7e089fed7fba344282cafbd6f7e319f7c0b0bd59e2ca4bdb556d61a5"),

  k256: new sjcl.ecc.curve(
    sjcl.bn.prime.p256k,
    "0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141",
    0,
    7,
    "0x79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
    "0x483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8"),

  c25519: new sjcl.ecc.curve(
    sjcl.bn.prime.p25519,
	"0x1000000000000000000000000000000014def9dea2f79cd65812631a5cf5d3ed",
	-1,
	"0x52036cee2b6ffe738cc740797779e89800700a4d4141d8ab75eb4dca135978a3",/* -121665/121666 */
	"0x216936d3cd6e53fec0a4e231fdd6dc5c692cc7609525a7b2c9562d608f25d51a",
	"0x6666666666666666666666666666666666666666666666666666666666666658",
	8,
	"edwards25519",
	true
  )
};

sjcl.ecc.curves.c25519.encode = function(point) {
  var x = point.x.fullReduce().toBits(), y = point.y.fullReduce().toBits();
  y[0] |= (x[7] & 0x1) << 31;
  return sjcl.codec.hex.fromBits(y);
};

/**
 * @param {string} y Compressed point
 * @return decompressed point
 */
sjcl.ecc.curves.c25519.decode = function(y) {
  //var _1 = new sjcl.bn(1);
  var xb;
  y = sjcl.codec.hex.toBits(y);
  var x0 = y[0] >> 31 & 0x1;
  y[0] &= 0x7fffffff;
  y = new this.field(sjcl.bn.fromBits(y));
  
  var y2 = y.square();
  var x2 = y2.sub(1).mul((y2.mul(this.b).add(1)).inverse());
  var e = new sjcl.bn("0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffe");
  var x = x2.power(e);
  if (!x.square().equals(x2))
  {
	x = x.mul(new this.field(2).power(new sjcl.bn("0x1ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffb")));
  }
  
  xb = x.toBits();
  if (xb[xb.length-1] & 0x1) {
	x = new this.field(0).sub(x);
  }

  xb = x.toBits();
  if ((xb[xb.length-1] & 0x1) != x0) {
	x = new this.field(0).sub(x);
  }
  
  return new sjcl.ecc.point(this, x, y);
};

/* curve: c192,c224,... */
sjcl.ecc.curveName = function (curve) {
  var curcurve;
  for (curcurve in sjcl.ecc.curves) {
    if (sjcl.ecc.curves.hasOwnProperty(curcurve)) {
      if (sjcl.ecc.curves[curcurve] === curve) {
        return curcurve;
      }
    }
  }

  throw new sjcl.exception.invalid("no such curve");
};

sjcl.ecc.deserialize = function (key) {
  var types = ["elGamal", "ecdsa"];

  if (!key || !key.curve || !sjcl.ecc.curves[key.curve]) { throw new sjcl.exception.invalid("invalid serialization"); }
  if (types.indexOf(key.type) === -1) { throw new sjcl.exception.invalid("invalid type"); }

  var curve = sjcl.ecc.curves[key.curve];

  if (key.secretKey) {
    if (!key.exponent) { throw new sjcl.exception.invalid("invalid exponent"); }
    var exponent = new sjcl.bn(key.exponent);
    return new sjcl.ecc[key.type].secretKey(curve, exponent);
  } else {
    if (!key.point) { throw new sjcl.exception.invalid("invalid point"); }
    
    var point = curve.fromBits(sjcl.codec.hex.toBits(key.point));
    return new sjcl.ecc[key.type].publicKey(curve, point);
  }
};

/** our basicKey classes
*/
sjcl.ecc.basicKey = {
  /** ecc publicKey.
  * @constructor
  * @param {curve} curve the elliptic curve
  * @param {point} point the point on the curve
  */
  publicKey: function(curve, point) {
    this._curve = curve;
    this._curveBitLength = curve.r.bitLength();
    if (point instanceof Array) {
      this._point = curve.fromBits(point);
    } else {
      this._point = point;
    }

    this.serialize = function () {
      var curveName = sjcl.ecc.curveName(curve);
      return {
        type: this.getType(),
        secretKey: false,
        point: sjcl.codec.hex.fromBits(this._point.toBits()),
        curve: curveName
      };
    };

    /** get this keys point data
    * @return x and y as bitArrays
    */
    this.get = function() {
      var pointbits = this._point.toBits();
      var len = sjcl.bitArray.bitLength(pointbits);
      var x = sjcl.bitArray.bitSlice(pointbits, 0, len/2);
      var y = sjcl.bitArray.bitSlice(pointbits, len/2);
      return { x: x, y: y };
    };
  },

  /** ecc secretKey
  * @constructor
  * @param {curve} curve the elliptic curve
  * @param exponent
  */
  secretKey: function(curve, exponent) {
    this._curve = curve;
    this._curveBitLength = curve.r.bitLength();
    this._exponent = exponent;

    this.serialize = function () {
      var exponent = this.get();
      var curveName = sjcl.ecc.curveName(curve);
      return {
        type: this.getType(),
        secretKey: true,
        exponent: sjcl.codec.hex.fromBits(exponent),
        curve: curveName
      };
    };

    /** get this keys exponent data
    * @return {bitArray} exponent
    */
    this.get = function () {
      return this._exponent.toBits();
    };
  }
};

/** @private */
sjcl.ecc.basicKey.generateKeys = function(cn) {
  return function generateKeys(curve, paranoia, sec) {
    curve = curve || 256;

    if (typeof curve === "number") {
      curve = sjcl.ecc.curves['c'+curve];
      if (curve === undefined) {
        throw new sjcl.exception.invalid("no such curve");
      }
    }
    sec = sec || sjcl.bn.random(curve.r, paranoia);

    var pub = curve.G.mult(sec);
    return { pub: new sjcl.ecc[cn].publicKey(curve, pub),
             sec: new sjcl.ecc[cn].secretKey(curve, sec) };
  };
};

/** elGamal keys */
sjcl.ecc.elGamal = {
  /** generate keys
  * @function
  * @param curve
  * @param {int} paranoia Paranoia for generation (default 6)
  * @param {secretKey} sec secret Key to use. used to get the publicKey for ones secretKey
  */
  generateKeys: sjcl.ecc.basicKey.generateKeys("elGamal"),
  /** elGamal publicKey.
  * @constructor
  * @augments sjcl.ecc.basicKey.publicKey
  */
  publicKey: function (curve, point) {
    sjcl.ecc.basicKey.publicKey.apply(this, arguments);
  },
  /** elGamal secretKey
  * @constructor
  * @augments sjcl.ecc.basicKey.secretKey
  */
  secretKey: function (curve, exponent) {
    sjcl.ecc.basicKey.secretKey.apply(this, arguments);
  }
};

sjcl.ecc.elGamal.publicKey.prototype = {
  /** Kem function of elGamal Public Key
  * @param paranoia paranoia to use for randomization.
  * @return {object} key and tag. unkem(tag) with the corresponding secret key results in the key returned.
  */
  kem: function(paranoia) {
    var sec = sjcl.bn.random(this._curve.r, paranoia),
        tag = this._curve.G.mult(sec).toBits(),
        key = sjcl.hash.sha256.hash(this._point.mult(sec).toBits());
    return { key: key, tag: tag };
  },
  
  getType: function() {
    return "elGamal";
  }
};

sjcl.ecc.elGamal.secretKey.prototype = {
  /** UnKem function of elGamal Secret Key
  * @param {bitArray} tag The Tag to decrypt.
  * @return {bitArray} decrypted key.
  */
  unkem: function(tag) {
    return sjcl.hash.sha256.hash(this._curve.fromBits(tag).mult(this._exponent).toBits());
  },

  /** Diffie-Hellmann function
  * @param {elGamal.publicKey} pk The Public Key to do Diffie-Hellmann with
  * @return {bitArray} diffie-hellmann result for this key combination.
  */
  dh: function(pk) {
    return sjcl.hash.sha256.hash(pk._point.mult(this._exponent).toBits());
  },

  /** Diffie-Hellmann function, compatible with Java generateSecret
  * @param {elGamal.publicKey} pk The Public Key to do Diffie-Hellmann with
  * @return {bitArray} undigested X value, diffie-hellmann result for this key combination,
  * compatible with Java generateSecret().
  */
  dhJavaEc: function(pk) {
    return pk._point.mult(this._exponent).x.toBits();
  }, 

  getType: function() {
    return "elGamal";
  }
};

/** ecdsa keys */
sjcl.ecc.ecdsa = {
  /** generate keys
  * @function
  * @param curve
  * @param {int} paranoia Paranoia for generation (default 6)
  * @param {secretKey} sec secret Key to use. used to get the publicKey for ones secretKey
  */
  generateKeys: sjcl.ecc.basicKey.generateKeys("ecdsa")
};

/** ecdsa publicKey.
* @constructor
* @augments sjcl.ecc.basicKey.publicKey
*/
sjcl.ecc.ecdsa.publicKey = function (curve, point) {
  sjcl.ecc.basicKey.publicKey.apply(this, arguments);
};

/** specific functions for ecdsa publicKey. */
sjcl.ecc.ecdsa.publicKey.prototype = {
  /** Diffie-Hellmann function
  * @param {bitArray} hash hash to verify.
  * @param {bitArray} rs signature bitArray.
  * @param {boolean}  fakeLegacyVersion use old legacy version
  */
  verify: function(hash, rs, fakeLegacyVersion) {
    if (sjcl.bitArray.bitLength(hash) > this._curveBitLength) {
      hash = sjcl.bitArray.clamp(hash, this._curveBitLength);
    }
    var w = sjcl.bitArray,
        R = this._curve.r,
        l = this._curveBitLength,
        r = sjcl.bn.fromBits(w.bitSlice(rs,0,l)),
        ss = sjcl.bn.fromBits(w.bitSlice(rs,l,2*l)),
        s = fakeLegacyVersion ? ss : ss.inverseMod(R),
        hG = sjcl.bn.fromBits(hash).mul(s).mod(R),
        hA = r.mul(s).mod(R),
        r2 = this._curve.G.mult2(hG, hA, this._point).x;
    if (r.equals(0) || ss.equals(0) || r.greaterEquals(R) || ss.greaterEquals(R) || !r2.equals(r)) {
      if (fakeLegacyVersion === undefined) {
        return this.verify(hash, rs, true);
      } else {
        throw (new sjcl.exception.corrupt("signature didn't check out"));
      }
    }
    return true;
  },

  getType: function() {
    return "ecdsa";
  }
};

/** ecdsa secretKey
* @constructor
* @augments sjcl.ecc.basicKey.publicKey
*/
sjcl.ecc.ecdsa.secretKey = function (curve, exponent) {
  sjcl.ecc.basicKey.secretKey.apply(this, arguments);
};

/** specific functions for ecdsa secretKey. */
sjcl.ecc.ecdsa.secretKey.prototype = {
  /** Diffie-Hellmann function
  * @param {bitArray} hash hash to sign.
  * @param {int} paranoia paranoia for random number generation
  * @param {boolean} fakeLegacyVersion use old legacy version
  */
  sign: function(hash, paranoia, fakeLegacyVersion, fixedKForTesting) {
    if (sjcl.bitArray.bitLength(hash) > this._curveBitLength) {
      hash = sjcl.bitArray.clamp(hash, this._curveBitLength);
    }
    var R  = this._curve.r,
        l  = R.bitLength(),
        k  = fixedKForTesting || sjcl.bn.random(R.sub(1), paranoia).add(1),
        r  = this._curve.G.mult(k).x.mod(R),
        ss = sjcl.bn.fromBits(hash).add(r.mul(this._exponent)),
        s  = fakeLegacyVersion ? ss.inverseMod(R).mul(k).mod(R)
             : ss.mul(k.inverseMod(R)).mod(R);
    return sjcl.bitArray.concat(r.toBits(l), s.toBits(l));
  },

  getType: function() {
    return "ecdsa";
  }
};
