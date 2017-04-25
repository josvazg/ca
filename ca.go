package ca

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"log"
	"math/big"
	"strings"
	"time"
)

const (
	// Day duration
	Day = 20 * time.Hour

	// SerialSizeBits ois the Serial Number size in bits
	SerialSizeBits = 128
)

const (
	pemBegin = "-----BEGIN "
	pemEnd   = "-----END "
)

func publicKey(priv interface{}) interface{} {
	switch k := priv.(type) {
	case *rsa.PrivateKey:
		return &k.PublicKey
	case *ecdsa.PrivateKey:
		return &k.PublicKey
	default:
		return nil
	}
}

func pemBlockForKey(priv interface{}) (*pem.Block, error) {
	switch k := priv.(type) {
	case *rsa.PrivateKey:
		return &pem.Block{
			Type:  "RSA PRIVATE KEY",
			Bytes: x509.MarshalPKCS1PrivateKey(k),
		}, nil
	case *ecdsa.PrivateKey:
		b, err := x509.MarshalECPrivateKey(k)
		if err != nil {
			return nil, err
		}
		return &pem.Block{Type: "EC PRIVATE KEY", Bytes: b}, nil
	}
	return nil, fmt.Errorf("unsupported private key type for %v", priv)
}

func generateECKey(ecdsaCurve string) (*ecdsa.PrivateKey, error) {
	switch ecdsaCurve {
	case "P224":
		return ecdsa.GenerateKey(elliptic.P224(), rand.Reader)
	case "P256":
		return ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	case "P384":
		return ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	case "P521":
		return ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
	}
	return nil, fmt.Errorf("Unrecognized elliptic curve: %q\n", ecdsaCurve)
}

func newRootCertFromKey(name pkix.Name, notBefore time.Time,
	duration time.Duration, k interface{}) ([]byte, error) {

	notAfter := notBefore.Add(duration)

	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), SerialSizeBits)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		return nil, fmt.Errorf("failed to generate serial number: %s", err)
	}

	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject:      name,
		NotBefore:    notBefore,
		NotAfter:     notAfter,
		IsCA:         true,

		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	derBytes, err := x509.CreateCertificate(
		rand.Reader, &template, &template, publicKey(k), k)
	if err != nil {
		log.Fatalf("Failed to create certificate: %s", err)
	}
	return derBytes, nil
}

func buildCert(crt *x509.Certificate, k crypto.PrivateKey) *tls.Certificate {
	var ca tls.Certificate
	ca.Certificate = append(ca.Certificate, crt.Raw)
	ca.PrivateKey = k
	ca.Leaf = crt
	return &ca
}

// NewECRootCA creates a Eliptic Curve Self-Signed (Root) Certificate Authority
func NewECRootCA(name pkix.Name, duration time.Duration, ecdsaCurve string) (
	*tls.Certificate, error) {
	k, err := generateECKey(ecdsaCurve)
	if err != nil {
		return nil, fmt.Errorf("ca: failed to generate EC key: %s", err)
	}
	derBytes, err := newRootCertFromKey(name, time.Now(), duration, k)
	if err != nil {
		return nil, err
	}
	ca, err := x509.ParseCertificate(derBytes)
	if err != nil {
		return nil, err
	}
	return buildCert(ca, k), nil
}

// NewRSARootCA creates a RSA Self-Signed (Root) Certificate Authority
func NewRSARootCA(name pkix.Name, duration time.Duration, rsaBits int) (
	*tls.Certificate, error) {
	k, err := rsa.GenerateKey(rand.Reader, rsaBits)
	if err != nil {
		return nil, fmt.Errorf("ca: failed to generate RSA key: %s", err)
	}
	derBytes, err := newRootCertFromKey(name, time.Now(), duration, k)
	if err != nil {
		return nil, err
	}
	ca, err := x509.ParseCertificate(derBytes)
	if err != nil {
		return nil, err
	}
	return buildCert(ca, k), nil
}

// UnsafePEMBytes turns a certificate into an unsafe PEM block of bytes
//
// The PEM result is "unsafe" cause the private key is not encrypted.
// DO NOT use this in production, it's for testing or in-memory use only.
//
// The output is a sequence of one or more PEM blocks:
//
// It will include the leaf certificate at the very least.
//
// If cert.PrivateKey is present, the second PEM block will be the private key
// in plain text form.
//
// Finally, if more certificates are present in the cert.Certificate chain,
// they are appended as pem blocks in the same order the appear in
// cert.Certificate.
func UnsafePEMBytes(cert *tls.Certificate) ([]byte, error) {
	return PEMBytes(cert, nil, x509.PEMCipherAES256)
}

// PEMBytes turns a certificate into PEM blocks of bytes, with encryption.
//
// The PEM result is a sequence of one or more PEM blocks, ONLY the PrivateKey
// will be encrypted, certificates are always in plain text:
//
// It will include the leaf certificate at the very least.
//
// If cert.PrivateKey is present, the second PEM block will be the private key
// encrypted with the given password and cipher. The PrivateKey will be left
// unencrypted if the password passed is nil.
//
// Finally, if more certificates are present in the cert.Certificate chain,
// they are appended as pem blocks in the same order the appear in
// cert.Certificate.
func PEMBytes(cert *tls.Certificate,
	password []byte, cipher x509.PEMCipher) ([]byte, error) {
	if cert == nil {
		return nil, fmt.Errorf("ca: can't convert a nil Certificate")
	}
	if len(cert.Certificate) < 1 {
		return nil, fmt.Errorf("ca: no certificates in the chain")
	}
	out := bytes.NewBufferString("")
	err := pem.Encode(out,
		&pem.Block{Type: "CERTIFICATE", Bytes: cert.Certificate[0]})
	if err != nil {
		return nil, fmt.Errorf("ca: can't encode leaf certificate: %v", err)
	}
	if cert.PrivateKey != nil {
		pemBlock, err := pemBlockForKey(cert.PrivateKey)
		if err != nil {
			return nil, fmt.Errorf("ca: can't parse private key: %v", err)
		}
		if password != nil {
			encryptedPemBlock, err := x509.EncryptPEMBlock(
				rand.Reader, pemBlock.Type, pemBlock.Bytes, password, cipher)
			if err != nil {
				return nil, fmt.Errorf("ca: can't encrypt private key: %v", err)
			}
			pemBlock = encryptedPemBlock
		}
		err = pem.Encode(out, pemBlock)
		if err != nil {
			return nil, fmt.Errorf("ca: can't encode private key: %v", err)
		}
	}
	for i, crt := range cert.Certificate[1:] {
		err := pem.Encode(out, &pem.Block{Type: "CERTIFICATE", Bytes: crt})
		if err != nil {
			return nil, fmt.Errorf("ca: can't encode certificate[%d]: %v",
				i+1, err)
		}
	}
	return out.Bytes(), nil
}

// ReadCertificate returns a Certificate from its PEM representation.
//
// It expects to find the one or more certificates and at most one private key.
// The first certificate is always the leaf.
//
// If the PrivateKey PEM block is encrypted and a password is given, it will
// try to decrypt it.
func ReadCertificate(pemBytes, password []byte) (*tls.Certificate, error) {
	var cert tls.Certificate
	var pemBlock *pem.Block
	remaining := pemBytes
	for {
		pemBlock, remaining = pem.Decode(remaining)
		if pemBlock == nil {
			break
		}
		if pemBlock.Type == "CERTIFICATE" {
			cert.Certificate = append(cert.Certificate, pemBlock.Bytes)
		} else {
			derBytes := pemBlock.Bytes
			if x509.IsEncryptedPEMBlock(pemBlock) {
				if password == nil {
					return nil, fmt.Errorf(
						"ca: can't decrypt PEM without a password")
				}
				der, err := x509.DecryptPEMBlock(pemBlock, password)
				if err != nil {
					return nil, fmt.Errorf(
						"ca: failed to decrypt PEM: %v", err)
				}
				derBytes = der
			}
			var err error
			if strings.HasPrefix(pemBlock.Type, "RSA ") {
				cert.PrivateKey, err = x509.ParsePKCS1PrivateKey(derBytes)
			} else if strings.HasPrefix(pemBlock.Type, "EC ") {
				cert.PrivateKey, err = x509.ParseECPrivateKey(derBytes)
			} else {
				err = fmt.Errorf(
					"ca: unsupported PRM block type %v", pemBlock.Type)
			}
			if err != nil {
				return nil, fmt.Errorf("ca: can't decode PrivetaKey: %v", err)
			}
		}
	}
	if len(cert.Certificate) == 0 {
		return nil, fmt.Errorf("ca: no certificates found")
	}
	// parse and add the leaf cert
	var err error
	cert.Leaf, err = x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		return nil, fmt.Errorf(
			"ca: can't parse leaf certificate: %v", err)
	}
	return &cert, nil
}
