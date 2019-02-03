package gopaque

import (
	"go.dedis.ch/kyber"
)

func oprfUserStep1(crypto Crypto, x []byte) (r kyber.Scalar, alpha kyber.Point) {
	// r = random
	r = crypto.Scalar().Pick(crypto.RandomStream())
	// alpha = cyclic-group-hash(x)^r
	return r, crypto.HashToPoint(x).Mul(r, nil)
}

func oprfServerStep2(alpha kyber.Point, k kyber.Scalar) (beta kyber.Point) {
	// TODO: validation
	// beta = alpha^k
	return alpha.Clone().Mul(k, nil)
}

func oprfUserStep3(crypto Crypto, x []byte, r kyber.Scalar, beta kyber.Point) (out []byte) {
	// H(x, beta^{1/r})
	h := crypto.Hash()
	toHash := beta.Clone().Mul(crypto.Scalar().Inv(r), nil)
	if b, err := toHash.MarshalBinary(); err != nil {
		panic(err)
	} else if _, err = h.Write(b); err != nil {
		panic(err)
	}
	return h.Sum(nil)
}
