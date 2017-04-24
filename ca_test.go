package ca

import (
	"bytes"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"testing"
)

var name = pkix.Name{
	CommonName: "TestCA",
}

func dieOnError(t *testing.T, err error) {
	if err != nil {
		t.Fatal(err)
	}
}

func assertSame(data0, data1 []byte) error {
	if len(data0) != len(data1) {
		return fmt.Errorf("data0 is %d bytes long, while data1 is %d",
			len(data0), len(data1))
	}
	for i, b := range data0 {
		if data1[i] != b {
			return fmt.Errorf("data0[%d] = 0x%x != data1[%d] = 0x%x",
				i, b, i, data1[i])
		}
	}
	return nil
}

func verifyRootCA(t *testing.T, ca *x509.Certificate) {
	certPool := x509.NewCertPool()
	certPool.AddCert(ca)
	_, err := ca.Verify(x509.VerifyOptions{Roots: certPool})
	dieOnError(t, err)
}

func TestNewRSARootCA(t *testing.T) {
	ca, k, err := NewRSARootCA(name, 365*Day, 2048)
	dieOnError(t, err)
	verifyRootCA(t, ca)
	// validate key
	dieOnError(t, k.Validate())
}

func TestNewECRootCA(t *testing.T) {
	ca, _, err := NewECRootCA(name, 365*Day, "P521")
	dieOnError(t, err)
	verifyRootCA(t, ca)
}

func TestPEMEncondings(t *testing.T) {
	ca, k, err := NewECRootCA(name, 365*Day, "P521")
	dieOnError(t, err)
	// encode/decode cert test
	caPem := bytes.NewBufferString("")
	dieOnError(t, EncodePEMCert(caPem, ca))
	ca2, err := DecodePEMCert(caPem.String())
	dieOnError(t, err)
	dieOnError(t, assertSame(ca.Raw, ca2.Raw))
	// encode/decode plain text key
	keyPem := bytes.NewBufferString("")
	dieOnError(t, EncodePEMKey(keyPem, k))
	_, err = DecodePEMKey(keyPem.String(), nil)
	dieOnError(t, err)
	//endoce/decode empcrypted key
	encryptedKeyPem := bytes.NewBufferString("")
	pass := []byte("somepassword")
	dieOnError(t, EncryptPEMKey(encryptedKeyPem, k, pass, x509.PEMCipherAES256))
	_, err = DecodePEMKey(keyPem.String(), pass)
	dieOnError(t, err)
}

func TestNextPEM(t *testing.T) {
}
