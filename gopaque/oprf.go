package gopaque

import (
	"go.dedis.ch/kyber"
	"go.dedis.ch/kyber/suites"
)

func oprfUserStep1(suite suites.Suite, x []byte) (r kyber.Scalar, alpha kyber.Point) {
	// r = random
	r = suite.Scalar().Pick(o.Suite.RandomStream())
	// alpha = cyclic-group-hash(x)^r
	return r, hashToPoint(suite, x).Mul(r, nil)
}

func oprfServerStep2(alpha kyber.Point, k kyber.Scalar) (beta kyber.Point) {
	// TODO: validation
	// beta = alpha^k
	return alpha.Clone().Mul(k, nil)
}

func oprfUserStep3(suite suites.Suite, x []byte, r kyber.Scalar, beta kyber.Point) (out []byte) {
	// H(x, beta^{1/r})
	h := suite.Hash()
	toHash := beta.Clone().Mul(suite.Scalar().Inv(r), nil)
	if b, err := toHash.MarshalBinary(); err != nil {
		panic(err)
	} else if _, err = h.Write(b); err != nil {
		panic(err)
	}
	return h.Sum(nil)
}

func hashToPoint(suite suites.Suite, msg []byte) hyper.Point {
	// TODO: Since functionality was removed in https://github.com/dedis/kyber/pull/352, we just copied the BLS
	// code but we need to reintroduce proper elligator or something when it's back.
	h := suite.Hash()
	h.Write(msg)
	x := suite.Scalar().SetBytes(h.Sum(nil))
	return suite.Point().Mul(x, nil)
}
