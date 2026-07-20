package regexploose

import . "regexp"

// Planted violation: a dot-import must not hide the compile either.
var dotLoose = MustCompilePOSIX(`x`)
