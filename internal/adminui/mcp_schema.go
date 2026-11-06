package adminui

import (
	"bytes"
	"encoding/json"
	"fmt"
	"reflect"
	"slices"
	"strings"

	"github.com/andychoi/mock-oidc/internal/jsonx"
)

type inputSpec struct {
	schema   jsonx.Obj
	required []string
	enums    map[string][]string
}

func specFor(t reflect.Type) inputSpec {
	if t.Kind() != reflect.Struct {
		panic("adminui: tool input must be a struct, got " + t.String())
	}
	spec := inputSpec{enums: map[string][]string{}}
	props := jsonx.Obj{}
	for _, f := range jsonFields(t) {
		prop := schemaFor(f.Type, t.String()+"."+f.Name)
		if e := f.Tag.Get("enum"); e != "" {
			if f.Type.Kind() != reflect.String {
				panic("adminui: enum tag on non-string field " + t.String() + "." + f.Name)
			}
			spec.enums[jsonName(f)] = strings.Split(e, ",")
			prop = append(prop, jsonx.Field{Name: "enum", V: spec.enums[jsonName(f)]})
		}
		if d := f.Tag.Get("desc"); d != "" {
			prop = append(prop, jsonx.Field{Name: "description", V: d})
		}
		if f.Tag.Get("mcp") == "required" {
			spec.required = append(spec.required, jsonName(f))
		}
		props = append(props, jsonx.Field{Name: jsonName(f), V: prop})
	}
	spec.schema = jsonx.Obj{{Name: "type", V: "object"}, {Name: "properties", V: props}}
	if len(spec.required) > 0 {
		spec.schema = append(spec.schema, jsonx.Field{Name: "required", V: spec.required})
	}
	spec.schema = append(spec.schema, jsonx.Field{Name: "additionalProperties", V: false})
	return spec
}

func schemaFor(t reflect.Type, where string) jsonx.Obj {
	switch t.Kind() {
	case reflect.String:
		return jsonx.Obj{{Name: "type", V: "string"}}
	case reflect.Bool:
		return jsonx.Obj{{Name: "type", V: "boolean"}}
	case reflect.Int, reflect.Int32, reflect.Int64:
		return jsonx.Obj{{Name: "type", V: "integer"}}
	case reflect.Pointer:
		return schemaFor(t.Elem(), where)
	case reflect.Slice:
		return jsonx.Obj{{Name: "type", V: "array"}, {Name: "items", V: schemaFor(t.Elem(), where+"[]")}}
	case reflect.Struct:
		props := jsonx.Obj{}
		for _, f := range jsonFields(t) {
			props = append(props, jsonx.Field{Name: jsonName(f), V: schemaFor(f.Type, where+"."+f.Name)})
		}
		return jsonx.Obj{{Name: "type", V: "object"}, {Name: "properties", V: props}, {Name: "additionalProperties", V: false}}
	}
	panic(fmt.Sprintf("adminui: no JSON Schema for %s (%s)", where, t))
}

func jsonFields(t reflect.Type) []reflect.StructField {
	var out []reflect.StructField
	for i := range t.NumField() {
		f := t.Field(i)
		if !f.IsExported() || f.Tag.Get("json") == "-" {
			continue
		}
		if f.Anonymous {
			panic("adminui: embedded field " + t.String() + "." + f.Name + " is not supported in tool inputs")
		}
		out = append(out, f)
	}
	return out
}

func jsonName(f reflect.StructField) string {
	name, _, _ := strings.Cut(f.Tag.Get("json"), ",")
	if name == "" {
		return f.Name
	}
	return name
}

func strictDecode(raw json.RawMessage, spec inputSpec, out any) error {
	if len(bytes.TrimSpace(raw)) == 0 || string(bytes.TrimSpace(raw)) == "null" {
		raw = json.RawMessage("{}")
	}
	var present map[string]json.RawMessage
	if err := json.Unmarshal(raw, &present); err != nil {
		return fmt.Errorf("arguments must be a JSON object: %w", err)
	}
	for _, name := range spec.required {
		if v, ok := present[name]; !ok || string(v) == "null" {
			return fmt.Errorf("missing required argument %q", name)
		}
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(out); err != nil {
		return fmt.Errorf("invalid arguments: %w", err)
	}
	for name, allowed := range spec.enums {
		v, ok := present[name]
		if !ok {
			continue
		}
		var s string
		_ = json.Unmarshal(v, &s)
		if !slices.Contains(allowed, s) {
			return fmt.Errorf("argument %q must be one of %s", name, strings.Join(allowed, ", "))
		}
	}
	return nil
}
