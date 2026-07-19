// Fixture: secret-pattern fields as inline values (flagged) and their
// path-typed forms (clean); dbSection is a named same-package section.
package fixture

type appConfig struct {
	Auth struct {
		Token     string
		TokenFile string
	}
	DB dbSection
}

type dbSection struct {
	Password     string
	PasswordFile string
}
