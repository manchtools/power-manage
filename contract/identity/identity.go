// Package identity carries the certificate-profile constants of SPEC-003
// §3.5 ([WIRE-18]): identity at every seam is the mTLS certificate — SPIFFE
// URI SAN = class, CN = instance ULID, DNS SAN = server name only. No
// message anywhere in the contract carries a self-asserted identity field.
// Parsing and enforcement live with PKI issuance (SPEC-006) and
// authentication (SPEC-007); this package only fixes the profile values.
package identity

const (
	// SPIFFETrustDomain is the single trust domain of the deployment.
	SPIFFETrustDomain = "power-manage"

	// The three certificate classes. The URI SAN carries exactly one of
	// these; the instance identity is the CN ULID, never a URI path.
	AgentSPIFFEURI   = "spiffe://power-manage/agent"
	GatewaySPIFFEURI = "spiffe://power-manage/gateway"
	ControlSPIFFEURI = "spiffe://power-manage/control"
)
