package squic

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"math/big"
	"testing"
	"time"
)

// The pinned key is the only thing authenticating the server: no CA, no chain,
// no hostname. Nothing tested the verifier, so these pin its behaviour — and
// the smuggled-key case in particular, which is the attack squic-rust was
// vulnerable to (SIP-9).

func edKeypair(t *testing.T) (ed25519.PrivateKey, ed25519.PublicKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	return priv, pub
}

// certDER self-signs a certificate for the given key, optionally carrying
// `smuggled` verbatim in an extension the verifier has no business reading.
func certDER(t *testing.T, priv crypto.Signer, pub any, smuggled []byte) []byte {
	t.Helper()
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "squic"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	if smuggled != nil {
		tmpl.ExtraExtensions = []pkix.Extension{{
			Id:    asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 99999, 1},
			Value: smuggled,
		}}
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, pub, priv)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}
	return der
}

func verifyPinned(pinned ed25519.PublicKey, ders ...[]byte) error {
	return ClientTLSConfig(pinned).VerifyPeerCertificate(ders, nil)
}

func TestPinnedKeyAcceptsTheServerItPinned(t *testing.T) {
	priv, pub := edKeypair(t)
	if err := verifyPinned(pub, certDER(t, priv, pub, nil)); err != nil {
		t.Fatalf("pinned key rejected its own certificate: %v", err)
	}
}

func TestPinnedKeyRejectsADifferentKey(t *testing.T) {
	priv, pub := edKeypair(t)
	_, other := edKeypair(t)
	if err := verifyPinned(other, certDER(t, priv, pub, nil)); err == nil {
		t.Fatal("a certificate for a different key was accepted")
	}
}

func TestPinnedKeyRejectsNoCertificate(t *testing.T) {
	_, pub := edKeypair(t)
	if err := verifyPinned(pub); err == nil {
		t.Fatal("a handshake presenting no certificate was accepted")
	}
}

func TestPinnedKeyRejectsAnUnparseableCertificate(t *testing.T) {
	_, pub := edKeypair(t)
	if err := verifyPinned(pub, []byte{0x30, 0x82, 0xff, 0xff, 0x00}); err == nil {
		t.Fatal("an unparseable certificate was accepted")
	}
}

// A sQUIC identity is an Ed25519 key. Any other key type cannot be the pinned
// identity, whatever else the certificate carries.
func TestPinnedKeyRejectsANonEd25519Key(t *testing.T) {
	_, pub := edKeypair(t)
	ec, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate ecdsa: %v", err)
	}
	if err := verifyPinned(pub, certDER(t, ec, &ec.PublicKey, pub)); err == nil {
		t.Fatal("a certificate with a non-Ed25519 key was accepted")
	}
}

// The pin must be on the SubjectPublicKeyInfo — the key that signs
// CertificateVerify — and not on the certificate's bytes as a whole. An
// attacker holding no part of the pinned identity can self-sign with their own
// key and paste the pinned key into any field they like; a verifier that
// searches the DER accepts it, and the handshake is then completed by the
// attacker's key.
func TestPinnedKeyRejectsACertificateThatMerelyContainsIt(t *testing.T) {
	_, victim := edKeypair(t)
	attackerPriv, attackerPub := edKeypair(t)

	der := certDER(t, attackerPriv, attackerPub, victim)
	if !containsBytes(der, victim) {
		t.Fatal("test setup failed: the pinned key is not present in the DER")
	}

	if err := verifyPinned(victim, der); err == nil {
		t.Fatal("a certificate signed by an attacker-controlled key was accepted " +
			"because it happened to contain the pinned key")
	}
}

func containsBytes(haystack, needle []byte) bool {
	for i := 0; i+len(needle) <= len(haystack); i++ {
		match := true
		for j := range needle {
			if haystack[i+j] != needle[j] {
				match = false
				break
			}
		}
		if match {
			return true
		}
	}
	return false
}
