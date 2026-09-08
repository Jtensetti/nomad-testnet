// Package durable holds the one directory-flush this repository uses.
//
// Five packages had their own copy of it and no two were the same: one
// swallowed io.EOF with no explanation, three ignored the error from Close,
// and only one reported both. They were also all wrong on Windows in the same
// way, which is what made the duplication expensive rather than merely untidy
// -- a platform fix would have had to be found and applied five times.
package durable

import "errors"

// ErrNotADirectory is returned when the path exists and is something else.
// Named so the platform implementations can agree on it: the flush differs
// between them, the error surface must not.
var ErrNotADirectory = errors.New("path is not a directory")
