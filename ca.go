package ca

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"io"
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
	pemStart = "----BEGIN "
	pemEnd   = "----END "
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

// NewECRootCA creates a Eliptic Curve Self-Signed (Root) Certificate Authority
func NewECRootCA(name pkix.Name, duration time.Duration, ecdsaCurve string) (
	*x509.Certificate, *ecdsa.PrivateKey, error) {
	k, err := generateECKey(ecdsaCurve)
	if err != nil {
		return nil, nil, fmt.Errorf(
			"failed to generate EC private key: %s", err)
	}
	derBytes, err := newRootCertFromKey(name, time.Now(), duration, k)
	if err != nil {
		return nil, nil, err
	}
	ca, err := x509.ParseCertificate(derBytes)
	if err != nil {
		return nil, nil, err
	}
	return ca, k, err
}

// NewRSARootCA creates a RSA Self-Signed (Root) Certificate Authority
func NewRSARootCA(name pkix.Name, duration time.Duration, rsaBits int) (
	*x509.Certificate, *rsa.PrivateKey, error) {
	k, err := rsa.GenerateKey(rand.Reader, rsaBits)
	if err != nil {
		return nil, nil, fmt.Errorf(
			"failed to generate RSA private key: %s", err)
	}
	derBytes, err := newRootCertFromKey(name, time.Now(), duration, k)
	if err != nil {
		return nil, nil, err
	}
	ca, err := x509.ParseCertificate(derBytes)
	if err != nil {
		return nil, nil, err
	}
	return ca, k, err
}

// EncodePEMCert writes a certificate as a PEM block to out
func EncodePEMCert(out io.Writer, cert *x509.Certificate) error {
	return pem.Encode(out, &pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})
}

// EncodePEMKey writes private key priv as a plain text PEM block to out
func EncodePEMKey(out io.Writer, priv interface{}) error {
	pemBlock, err := pemBlockForKey(priv)
	if err != nil {
		return err
	}
	return pem.Encode(out, pemBlock)
}

// EncryptPEMKey writes private key priv as an encrypted PEM block to out
func EncryptPEMKey(out io.Writer, priv interface{},
	password []byte, cipher x509.PEMCipher) error {
	pemBlock, err := pemBlockForKey(priv)
	if err != nil {
		return err
	}
	encryptedPemBlock, err := x509.EncryptPEMBlock(
		rand.Reader, pemBlock.Type, pemBlock.Bytes, password, cipher)
	if err != nil {
		return fmt.Errorf("failed to encrypt PEMBlock %v: %v", pemBlock, err)
	}
	return pem.Encode(out, encryptedPemBlock)
}

func readline(in io.Reader) ([]byte, error) {
	line := bytes.NewBuffer(nil)
	buf := make([]byte, 1)
	n, err := in.Read(buf)
	for n > 0 && err != nil {
		line.Write(buf)
		if buf[0] == '\n' {
			return line.Bytes(), nil
		}
		n, err = in.Read(buf)
	}
	if err != nil && err != io.EOF {
		return nil, nil
	}
	return line.Bytes(), nil
}

// NextPEM reads in until it gets the next full PEM block string.
//
// Returns the next PEM block string from in or an error
func NextPEM(in io.Reader, pass []byte) (string, error) {
	pem := bytes.NewBufferString("")
	line, err := readline(in)
	if err != nil {
		return "", err
	}
	if !bytes.HasPrefix(line, []byte(pemStart)) {
		return "", fmt.Errorf("Malformed PEM begin line: %s", line)
	}
	_, err = pem.Write(line)
	for err != nil {
		if bytes.HasPrefix(line, []byte(pemEnd)) {
			return pem.String(), nil
		}
		line, err = readline(in)
		if err != nil {
			return "", err
		}
		_, err = pem.Write(line)
	}
	if err != nil {
		return "", err
	}
	return pem.String(), nil
}

// DecodePEMCert converts a certificate PEM string to a Certificate.
//
// Returns the certificate or an error
func DecodePEMCert(certPem string) (*x509.Certificate, error) {
	pemBlock, _ := pem.Decode([]byte(certPem))
	cert, err := x509.ParseCertificate(pemBlock.Bytes)
	if err != nil {
		return nil, err
	}
	return cert, nil
}

// DecodePEMKey converts a key PEM string to a PrivateKey.
//
// Returns the DER bytes of the key PEM string or an error
func DecodePEMKey(keyPem string, pass []byte) (interface{}, error) {
	pemBlock, _ := pem.Decode([]byte(keyPem))
	if pass != nil && x509.IsEncryptedPEMBlock(pemBlock) {
		bytes, err := x509.DecryptPEMBlock(pemBlock, pass)
		if err != nil {
			return nil, err
		}
		pemBlock.Bytes = bytes
	}
	if strings.HasPrefix(pemBlock.Type, "RSA ") {
		return x509.ParsePKCS1PrivateKey(pemBlock.Bytes)
	} else if strings.HasPrefix(pemBlock.Type, "EC ") {
		return x509.ParseECPrivateKey(pemBlock.Bytes)
	}
	return x509.ParsePKCS8PrivateKey(pemBlock.Bytes)
}
