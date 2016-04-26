package gnupg

import (
	"bytes"
	"crypto"
	"io"
	"strconv"

	"github.com/benburkert/openpgp/algorithm"
	"github.com/benburkert/openpgp/encoding"
	"github.com/benburkert/openpgp/errors"
	"golang.org/x/crypto/ed25519"
)

func init() {
	algorithm.PublicKeyById[EdDSA.Id()] = EdDSA
}

// EdDSA contains the EdDSA constant from the OpenPGP EdDSA draft
// RFC. This has not been officially assigned, but is present in
// GnuPG.
const EdDSA = publicKey(22) // EdDSA (not yet assigned).

var (
	oidEd25519 = []byte{0x2b, 0x06, 0x01, 0x04, 0x01, 0xda, 0x47, 0x0f, 0x01}
)

type publicKey uint8

func (pk publicKey) Id() uint8        { return uint8(pk) }
func (pk publicKey) CanEncrypt() bool { return false }
func (pk publicKey) CanSign() bool    { return true }

func (pk publicKey) BitLength(pub crypto.PublicKey) (uint16, error) {
	return uint16(len(pub.([32]byte))), nil
}

func (pk publicKey) Encrypt(rand io.Reader, pub crypto.PublicKey, msg []byte, fingerprint [20]byte) ([]encoding.Field, error) {
	switch pk {
	default:
		return nil, errors.InvalidArgumentError("cannot encrypt to public key of type " + strconv.Itoa(int(pk.Id())))
	}
}

func (pk publicKey) Decrypt(rand io.Reader, priv crypto.PrivateKey, fields []encoding.Field, fingerprint [20]byte) ([]byte, error) {
	return nil, errors.UnsupportedError("EdDSA does not support decryption")
}

func (pk publicKey) Sign(rand io.Reader, priv crypto.PrivateKey, sigopt crypto.SignerOpts, msg []byte) ([]encoding.Field, error) {
	switch pk {
	case EdDSA:
		eddsaPriv, ok := priv.(ed25519.PrivateKey)
		if !ok {
			return nil, errors.InvalidArgumentError("cannot sign with wrong type of private key")
		}

		rs := ed25519.Sign(eddsaPriv, msg)

		return []encoding.Field{
			encoding.NewMPI(rs[:32]),
			encoding.NewMPI(rs[32:]),
		}, nil
	default:
		return nil, errors.UnsupportedError("public key algorithm: " + strconv.Itoa(int(pk)))
	}
}

func (pk publicKey) Verify(pub crypto.PublicKey, sigopt crypto.SignerOpts, hashed []byte, sig []encoding.Field) error {
	switch pk {
	case EdDSA:
		eddsapub, ok := pub.(ed25519.PublicKey)
		if !ok {
			return errors.InvalidArgumentError("cannot verify signature with wrong type of public key")
		}

		if len(sig) != 2 {
			return errors.InvalidArgumentError("cannot verify malformed signature")
		}
		sigR := sig[0].Bytes()
		sigS := sig[1].Bytes()

		eddsasig := make([]byte, ed25519.SignatureSize)
		copy(eddsasig[:32], sigR)
		copy(eddsasig[32:], sigS)

		if !ed25519.Verify(eddsapub, hashed, eddsasig) {
			return errors.SignatureError("EdDSA verification failure")
		}
		return nil
	default:
		return errors.SignatureError("Unsupported public key algorithm used in signature")
	}
}

func (pk publicKey) ParsePrivateKey(data []byte, pub crypto.PublicKey) (crypto.PrivateKey, error) {
	buf := bytes.NewBuffer(data)

	switch pk {
	case EdDSA:
		eddsaPub := pub.(ed25519.PublicKey)
		eddsaPriv := make(ed25519.PrivateKey, ed25519.PrivateKeySize)

		d := new(encoding.MPI)
		if _, err := d.ReadFrom(buf); err != nil {
			return nil, err
		}

		copy(eddsaPriv[:32], d.Bytes())
		copy(eddsaPriv[32:], eddsaPub[:])

		return eddsaPriv, nil
	}
	panic("impossible")
}

func (pk publicKey) ParsePublicKey(r io.Reader) (crypto.PublicKey, []encoding.Field, error) {
	switch pk {
	case EdDSA:
		oid := new(encoding.BitString)
		if _, err := oid.ReadFrom(r); err != nil {
			return nil, nil, err
		}

		if !bytes.Equal(oid.Bytes(), oidEd25519) {
			return nil, nil, errors.InvalidArgumentError("cannot encrypt with an unknown curve")
		}

		p := new(encoding.MPI)
		if _, err := p.ReadFrom(r); err != nil {
			return nil, nil, err
		}

		if len(p.Bytes()) != 33 {
			return nil, nil, errors.InvalidArgumentError("invalid EdDSA public key encoding")
		}

		eddsa := make(ed25519.PublicKey, ed25519.PublicKeySize)
		switch p.Bytes()[0] {
		case 0x04:
			// TODO: see _gcry_ecc_eddsa_ensure_compact in gcrypt
			panic("unimplemented")
		case 0x40:
			copy(eddsa[:], p.Bytes()[1:])
		default:
			panic("impossible")
		}

		return eddsa, []encoding.Field{oid, p}, nil
	default:
		return nil, nil, errors.UnsupportedError("public key type: " + strconv.Itoa(int(pk)))
	}
}

func (pk publicKey) ParseEncryptedKey(r io.Reader) ([]encoding.Field, error) {
	return nil, errors.UnsupportedError("EdDSA does not support session keys")
}

func (pk publicKey) ParseSignature(r io.Reader) ([]encoding.Field, error) {
	switch pk {
	case EdDSA:
		sigR := new(encoding.MPI)
		if _, err := sigR.ReadFrom(r); err != nil {
			return nil, err
		}
		sigS := new(encoding.MPI)
		if _, err := sigS.ReadFrom(r); err != nil {
			return nil, err
		}

		return []encoding.Field{sigR, sigS}, nil
	default:
		return nil, errors.UnsupportedError("public key type: " + strconv.Itoa(int(pk)))
	}
}

func (pk publicKey) SerializePrivateKey(w io.Writer, priv crypto.PrivateKey) error {
	eddsaPriv, ok := priv.(ed25519.PrivateKey)
	if !ok {
		return errors.InvalidArgumentError("cannot serialize wrong type of private key")
	}

	keySize := ed25519.PrivateKeySize - ed25519.PublicKeySize
	_, err := encoding.NewMPI(eddsaPriv[:keySize]).WriteTo(w)
	return err
}
