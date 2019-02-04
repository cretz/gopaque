package gopaque

import (
	"bytes"
	"encoding/binary"
	"io"

	"go.dedis.ch/kyber"
)

// ErrUnmarshalMoreData is when there is more data after unmarshalling.
type ErrUnmarshalMoreData struct {
	// Left is the number of bytes not handled.
	Left int
}

func (e *ErrUnmarshalMoreData) Error() string { return "Expected EOF, still more data" }

type buf struct {
	*bytes.Buffer
}

func newBuf(b []byte) *buf { return &buf{bytes.NewBuffer(b)} }

func (b *buf) AssertUnmarshalNoMoreData() error {
	if l := b.Len(); l > 0 {
		return &ErrUnmarshalMoreData{l}
	}
	return nil
}

func (b *buf) ReadPoint(p kyber.Point) error {
	_, err := p.UnmarshalFrom(b)
	return err
}

func (b *buf) WritePoint(p kyber.Point) error {
	_, err := p.MarshalTo(b)
	return err
}

func (b *buf) ReadVarBytes() ([]byte, error) {
	var l uint32
	binary.Read(b, binary.BigEndian, &l)
	if b.Len() < int(l) {
		return nil, io.EOF
	}
	byts := make([]byte, l)
	b.Read(byts)
	return byts, nil
}

func (b *buf) WriteVarBytes(byts []byte) {
	binary.Write(b, binary.BigEndian, uint32(len(byts)))
	b.Write(byts)
}
