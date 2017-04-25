package ca

import (
	"crypto/rsa"
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
	ca, err := NewRSARootCA(name, 365*Day, 2048)
	dieOnError(t, err)
	verifyRootCA(t, ca.Leaf)
	// validate key
	pk := (ca.PrivateKey).(*rsa.PrivateKey)
	dieOnError(t, pk.Validate())
}

func TestNewECRootCA(t *testing.T) {
	ca, err := NewECRootCA(name, 365*Day, "P521")
	dieOnError(t, err)
	verifyRootCA(t, ca.Leaf)
}

func TestUnsafePEM(t *testing.T) {
	ca, err := NewECRootCA(name, 365*Day, "P521")
	dieOnError(t, err)
	if len(ca.Certificate) != 1 {
		t.Fatalf("Expected 1 cert at ca.Certificates but got %d",
			len(ca.Certificate))
	}
	pems, err := UnsafePEMBytes(ca)
	dieOnError(t, err)
	ca2, err := ReadCertificate(pems, nil)
	dieOnError(t, err)
	dieOnError(t, assertSame(ca.Certificate[0], ca2.Certificate[0]))
	if len(ca.Certificate) != len(ca2.Certificate) {
		t.Fatalf("Expected 1 cert at ca2.Certificates but got %d",
			len(ca2.Certificate))
	}
}

func TestPEM(t *testing.T) {
	ca, err := NewRSARootCA(name, 365*Day, 2048)
	dieOnError(t, err)
	if len(ca.Certificate) != 1 {
		t.Fatalf("Expected 1 cert at ca.Certificates but got %d",
			len(ca.Certificate))
	}
	pass := ([]byte)("somepassword")
	pems, err := PEMBytes(ca, pass, x509.PEMCipherAES256)
	dieOnError(t, err)
	ca2, err := ReadCertificate(pems, nil)
	dieOnError(t, err)
	dieOnError(t, assertSame(ca.Certificate[0], ca2.Certificate[0]))
	if len(ca.Certificate) != len(ca2.Certificate) {
		t.Fatalf("Expected 1 cert at ca2.Certificates but got %d",
			len(ca2.Certificate))
	}
}
