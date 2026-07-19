package sentinel

import "example.com/store"

// Clean: recognition goes through the store's recognizer, which matches
// both the domain sentinel and the raw driver error.
func isMissingClean(err error) bool { return store.IsNotFound(err) }
