// Package jsonx renders JSON in the exact style of the Kotlin server's Jackson
// pretty printer (2-space indent, `" : "` after keys, inline arrays), with
// insertion-ordered objects via Obj/Field.
package jsonx

import (
	"encoding/json"
	"math"
	"sort"
	"strconv"
	"strings"
)

// Field is one key/value pair of an ordered object.
type Field struct {
	Name string
	V    any
}

// Obj is an insertion-ordered JSON object.
type Obj []Field

// Arr is a JSON array.
type Arr []any

// Render renders a value (Obj, Arr, map, or scalar) in Jackson pretty style.
func Render(v any) string {
	var b strings.Builder
	renderValue(&b, v, 0)
	return b.String()
}

// RenderMap renders a Go map as an ordered object with sorted keys (the
// encoding/json order, used for free-form claim sets).
func RenderMap(m map[string]any) string {
	return Render(FromMap(m))
}

// FromMap converts a Go map to an Obj with sorted keys.
func FromMap(m map[string]any) Obj {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	obj := make(Obj, 0, len(keys))
	for _, k := range keys {
		obj = append(obj, Field{Name: k, V: m[k]})
	}
	return obj
}

const indentUnit = "  "

func renderValue(b *strings.Builder, v any, level int) {
	switch t := v.(type) {
	case Obj:
		renderObj(b, t, level)
	case map[string]any:
		renderObj(b, FromMap(t), level)
	case Arr:
		renderArr(b, t, level)
	case []string:
		arr := make(Arr, len(t))
		for i, s := range t {
			arr[i] = s
		}
		renderArr(b, arr, level)
	case []any:
		renderArr(b, t, level)
	case nil:
		b.WriteString("null")
	case string:
		b.WriteString(Quote(t))
	case bool:
		b.WriteString(strconv.FormatBool(t))
	case int:
		b.WriteString(strconv.Itoa(t))
	case int64:
		b.WriteString(strconv.FormatInt(t, 10))
	case float64:
		if t == math.Trunc(t) && math.Abs(t) < 1e15 {
			b.WriteString(strconv.FormatInt(int64(t), 10))
		} else {
			b.WriteString(strconv.FormatFloat(t, 'g', -1, 64))
		}
	case json.Number:
		b.WriteString(t.String())
	default:
		// Fallback: marshal via encoding/json without HTML escaping.
		enc, _ := marshalNoEscape(v)
		b.WriteString(enc)
	}
}

func renderObj(b *strings.Builder, obj Obj, level int) {
	if len(obj) == 0 {
		b.WriteString("{ }")
		return
	}
	inner := strings.Repeat(indentUnit, level+1)
	b.WriteString("{\n")
	for i, f := range obj {
		if i > 0 {
			b.WriteString(",\n")
		}
		b.WriteString(inner)
		b.WriteString(Quote(f.Name))
		b.WriteString(" : ")
		renderValue(b, f.V, level+1)
	}
	b.WriteString("\n")
	b.WriteString(strings.Repeat(indentUnit, level))
	b.WriteString("}")
}

func renderArr(b *strings.Builder, arr Arr, level int) {
	if len(arr) == 0 {
		b.WriteString("[ ]")
		return
	}
	b.WriteString("[ ")
	for i, e := range arr {
		if i > 0 {
			b.WriteString(", ")
		}
		if obj, ok := e.(Obj); ok {
			// Object elements keep their opening brace on the bracket line and
			// indent fields one level deeper than the array's own level:
			// "keys" : [ {
			//   "kty" : ...
			// } ]
			b.WriteString("{\n")
			inner := strings.Repeat(indentUnit, level+1)
			for j, f := range obj {
				if j > 0 {
					b.WriteString(",\n")
				}
				b.WriteString(inner)
				b.WriteString(Quote(f.Name))
				b.WriteString(" : ")
				renderValue(b, f.V, level+1)
			}
			b.WriteString("\n")
			b.WriteString(strings.Repeat(indentUnit, level))
			b.WriteString("}")
		} else if m, ok := e.(map[string]any); ok {
			renderArr(b, Arr{FromMap(m)}, level)
		} else {
			renderValue(b, e, level+1)
		}
	}
	b.WriteString(" ]")
}

// Quote JSON-quotes a string without HTML escaping.
func Quote(s string) string {
	var buf strings.Builder
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	_ = enc.Encode(s)
	return strings.TrimSuffix(buf.String(), "\n")
}

func marshalNoEscape(v any) (string, error) {
	var buf strings.Builder
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		return "", err
	}
	return strings.TrimSuffix(buf.String(), "\n"), nil
}
