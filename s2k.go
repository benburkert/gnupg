package gnupg

import (
	"bytes"
	"fmt"
	"io"
	"strconv"

	"github.com/benburkert/openpgp/algorithm"
	"github.com/benburkert/openpgp/errors"
	"github.com/benburkert/openpgp/s2k"
)

func init() {
	s2k.ParserById[0x65] = GNUExtension
}

// GNUExtension is a parser for GNU extensions to the string-to-key
// (S2K) specifications for OpenPGP.
func GNUExtension(r io.Reader) (s2k.S2K, error) {
	var buf [5]byte
	if _, err := io.ReadFull(r, buf[:]); err != nil {
		return nil, err
	}

	hash, ok := algorithm.HashById[buf[0]]
	if !ok {
		return nil, errors.UnsupportedError("hash for S2K function: " + strconv.Itoa(int(buf[0])))
	}

	if !bytes.Equal(buf[1:4], []byte("GNU")) {
		return nil, fmt.Errorf("missing 'GNU' marker for s2k")
	}

	parser, ok := ExtensionParserById[buf[4]]
	if !ok {
		return nil, errors.UnsupportedError("unknown GNU S2k extension specifier" + strconv.Itoa(int(buf[3])))
	}

	return parser(hash, r)
}

// ExtensionParserById is a mapping of S2K specifier IDs to their
// implementations. The use of Id is an artifact of the naming scheme
// from the extended Go crypto library's openpgp package, and is
// retained for consistency with that package.
var ExtensionParserById = map[uint8]ExtensionParser{
	0x1: Dummy,
}

type ExtensionParser func(algorithm.Hash, io.Reader) (s2k.S2K, error)

func Dummy(hash algorithm.Hash, r io.Reader) (s2k.S2K, error) {
	return &dummy{hash}, nil
}

// dummy is an implementation of the GNU Dummy S2K.
type dummy struct {
	hash algorithm.Hash
}

func (d *dummy) Id() uint8 { return 0x65 }

func (d *dummy) Convert(key, passphrase []byte) error {
	return errors.UnsupportedError("gnu-dummy does not support key decryption")
}

func (d *dummy) SetupIV(size int) ([]byte, error) {
	return []byte{}, nil
}

func (d *dummy) WriteTo(w io.Writer) (int, error) {
	return w.Write([]byte{0x65, d.hash.Id(), 0x47, 0x4e, 0x55})
}
