package gopaque_test

import (
	"testing"

	"github.com/cretz/gopaque/gopaque"
	"go.dedis.ch/kyber/v3"
)

func assert(t *testing.T, v bool, format string, args ...interface{}) {
	if !v {
		t.Fatalf(format, args...)
	}
}

func assertNoErr(t *testing.T, err error) {
	if err != nil {
		t.Fatal(err)
	}
}

func panicIfErr(err error) {
	if err != nil {
		panic(err)
	}
}

func pubKey(c gopaque.Crypto, priv kyber.Scalar) kyber.Point {
	return c.Point().Mul(priv, nil)
}
