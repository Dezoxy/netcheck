package report

import (
	"encoding/json"
	"io"
)

// WriteJSON marshals v as indented JSON and writes it to w, followed by a newline.
// Used by all four commands once they've projected their internal state into
// one of the *JSON wrapper types defined in jsonschema.go.
func WriteJSON(w io.Writer, v any) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	enc.SetEscapeHTML(false)
	return enc.Encode(v)
}
