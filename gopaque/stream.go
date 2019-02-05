package gopaque

import "io"

type readerStream struct {
	io.Reader
}

func (r *readerStream) XORKeyStream(dst, src []byte) {
	// Similar to the Kyber random stream...
	l := len(src)
	if len(dst) < l {
		panic("dst too short")
	}
	if _, err := io.ReadFull(r, dst[:l]); err != nil {
		panic(err)
	}
	for i := 0; i < l; i++ {
		dst[i] = src[i] ^ dst[i]
	}
}
