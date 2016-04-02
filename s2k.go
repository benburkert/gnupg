package gnupg

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"io"
	"io/ioutil"
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
	0x2: DivertToCard,
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

// DivertToCard is an implementation of the GNU S2K divert-to-card
// extension specifier for use with smart cards.
func DivertToCard(hash algorithm.Hash, r io.Reader) (s2k.S2K, error) {
	serial, err := ioutil.ReadAll(r)
	if err != nil {
		return nil, err
	}

	agent := agentForSerial(serial)
	if agent == nil {
		return nil, errors.UnsupportedError("no card agent for serial: " + hex.EncodeToString(serial))
	}

	return &divertToCard{
		agent:  agent,
		hash:   hash,
		serial: serial,
	}, nil
}

var agentRegistration = map[CardAgent][][]byte{}

func RegisterCardAgent(serial []byte, agent CardAgent) error {
	if agent := agentForSerial(serial); agent != nil {
		return errors.UnsupportedError("registered card agent exists for serial: " + hex.EncodeToString(serial))
	}

	agentRegistration[agent] = append(agentRegistration[agent], serial)
	return nil
}

func agentForSerial(serial []byte) CardAgent {
	for agent, serials := range agentRegistration {
		for i := range serials {
			if bytes.Equal(serial, serials[i]) {
				return agent
			}
		}
	}
	return nil
}

type CardAgent interface {
	ExtractPrivateKey(serial, passphrase []byte) ([]byte, error)
}

type divertToCard struct {
	agent  CardAgent
	hash   algorithm.Hash
	serial []byte
}

func (d *divertToCard) Id() uint8 { return 0x65 }

func (d *divertToCard) Convert(key, passphrase []byte) error {
	privKey, err := d.agent.ExtractPrivateKey(d.serial, passphrase)
	if err != nil {
		return err
	}

	if len(key) != len(privKey) {
		return errors.UnsupportedError("unexpected length of private key from card")
	}

	copy(key, privKey)
	return nil
}

func (d *divertToCard) SetupIV(size int) ([]byte, error) {
	// TODO: do we get the key data from the card here?
	panic("unimplemented")
}

func (d *divertToCard) WriteTo(w io.Writer) (int, error) {
	return w.Write(append([]byte{0x65, d.hash.Id(), 0x47, 0x4e, 0x55}, d.serial...))
}
