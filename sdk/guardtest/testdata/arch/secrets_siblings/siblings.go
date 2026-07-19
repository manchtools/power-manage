// Fixture: two sibling fields sharing one section type — the walk must
// descend under BOTH prefixes (a visited-set that never unwinds skips
// the second sibling's subtree).
package fixture

type replicaConfig struct {
	ReadDB  poolSection
	WriteDB poolSection
}

type poolSection struct {
	Passphrase     string
	PassphraseFile string
}
