package gopaque

import (
	"go.dedis.ch/kyber"
)

func oprfUserStep1(crypto Crypto, x []byte) (r kyber.Scalar, alpha kyber.Point) {
	// r = random
	r = crypto.Scalar().Pick(crypto.RandomStream())
	// alpha = cyclic-group-hash(x)^r
	alpha = crypto.HashToPoint(x)
	alpha.Mul(r, alpha)
	return
}

func oprfServerStep2(crypto Crypto, alpha kyber.Point, k kyber.Scalar) (v kyber.Point, beta kyber.Point) {
	// TODO: validation?
	// v = g^k
	v = crypto.Point().Base().Mul(k, nil)
	// beta = alpha^k
	return v, crypto.Point().Mul(k, alpha)
}

func oprfUserStep3(crypto Crypto, x []byte, r kyber.Scalar, v kyber.Point, beta kyber.Point) (out []byte) {
	// TODO: validation?
	// H(x, v, beta^{1/r})
	h := crypto.Hash()
	h.Write(x)
	b, _ := v.MarshalBinary()
	h.Write(b)
	b, _ = crypto.Point().Mul(crypto.Scalar().Inv(r), beta).MarshalBinary()
	h.Write(b)
	return h.Sum(nil)
}
