package auth

import "testing"

func TestInterfaceRequestSignature(t *testing.T) {
	const random = "random-value"
	// Cross-checked against SdpcBroker::signature in aTrust 2.4.10.50.
	const want = "72FFC52B0323D8E9A4A1626E282B8A16DFD3B30905A36B488BFC35C0FC96F543"

	if got := interfaceRequestSignature(random, []byte(`{"ticket":"abc"}`)); got != want {
		t.Fatalf("interfaceRequestSignature() = %q, want %q", got, want)
	}
}
