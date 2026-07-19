package listeners

import "crypto/tls"

// Registered in the fixture registrations against B4 — must NOT be a
// violation. A second listen call in the same function is covered by the
// same registration (recorded ceiling: one boundary per function).
func gatewayListen() error {
	l, err := tls.Listen("tcp", ":8443", nil)
	if err != nil {
		return err
	}
	return l.Close()
}
