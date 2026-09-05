package protocol

import (
	"bytes"
	"encoding/json"
	"io"
)

func newEncoder(w io.Writer) *json.Encoder {
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(false)
	return enc
}

// unmarshalStrict rejects trailing data after the JSON value so a frame cannot
// smuggle a second document.
func unmarshalStrict(frame []byte, target any) error {
	dec := json.NewDecoder(bytes.NewReader(frame))
	if err := dec.Decode(target); err != nil {
		return err
	}
	if dec.More() {
		return io.ErrUnexpectedEOF
	}
	return nil
}
