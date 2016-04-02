// Package gnupg implements GnuPG extensions to the OpenPGP (RFC 4880)
// specification. It includes support for EdDSA (Ed25519) private keys and
// gnu-dummy packets.
//
// There is a draft RFC that specifies EdDSA support in OpenPGP; this package
// implements version 04 of that draft, which is the most current draft. See
// docs/draft-koch-eddsa-for-openpgp-04.txt or
// http://www.ietf.org/id/draft-koch-eddsa-for-openpgp-04.txt.
//
// Interoperability testing is provided, given that the environment variable
// GNUPG_INTEROP_TEST=yes and GnuPG 2.1 is available.
package gnupg
