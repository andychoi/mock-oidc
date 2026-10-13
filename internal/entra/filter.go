package entra

import (
	"strings"
	"unicode"

	"github.com/andychoi/mock-oidc/internal/jsonx"
)

// This file implements the $filter subset of the Graph emulator (design:
// docs/entra/04-org-directory-design.md §3):
//
//	or      := and ("or" and)*
//	and     := unary ("and" unary)*
//	unary   := "not" unary | "(" or ")" | startsWith(path, 'lit')
//	         | path eq|ne lit | path in (lit, ...) | path/any(x: x eq lit)
//	lit     := 'string' ('' escapes a quote) | null | true | false
//
// A filter is evaluated against the full rendered entity (before $select), so
// $select-only properties such as onPremisesExtensionAttributes/extensionAttribute1
// are filterable. String comparison is case-insensitive, like directory
// queries. Anything outside the subset is refused rather than ignored.

type filterExpr interface {
	eval(e jsonx.Obj) bool
}

type filterOr []filterExpr
type filterAnd []filterExpr
type filterNot struct{ inner filterExpr }

func (f filterOr) eval(e jsonx.Obj) bool {
	for _, x := range f {
		if x.eval(e) {
			return true
		}
	}
	return false
}

func (f filterAnd) eval(e jsonx.Obj) bool {
	for _, x := range f {
		if !x.eval(e) {
			return false
		}
	}
	return true
}

func (f filterNot) eval(e jsonx.Obj) bool { return !f.inner.eval(e) }

// filterCmp is path eq|ne|in|startsWith literal(s).
type filterCmp struct {
	path []string
	op   string // "eq", "ne", "in", "startswith"
	lits []any  // string, bool or nil
}

func (f filterCmp) eval(e jsonx.Obj) bool {
	v := lookupPath(e, f.path)
	switch f.op {
	case "ne":
		return !literalEquals(v, f.lits[0])
	case "startswith":
		s, ok := v.(string)
		prefix, _ := f.lits[0].(string)
		return ok && strings.HasPrefix(strings.ToLower(s), strings.ToLower(prefix))
	}
	for _, lit := range f.lits {
		if literalEquals(v, lit) {
			return true
		}
	}
	return false
}

// filterAny is path/any(x: x eq lit) over a collection property.
type filterAny struct {
	path []string
	lit  any
}

func (f filterAny) eval(e jsonx.Obj) bool {
	arr, _ := lookupPath(e, f.path).(jsonx.Arr)
	for _, v := range arr {
		if literalEquals(v, f.lit) {
			return true
		}
	}
	return false
}

func literalEquals(v, lit any) bool {
	switch l := lit.(type) {
	case nil:
		return v == nil
	case bool:
		b, ok := v.(bool)
		return ok && b == l
	case string:
		s, ok := v.(string)
		return ok && strings.EqualFold(s, l)
	}
	return false
}

// lookupPath reads a (possibly nested) property, case-insensitively.
func lookupPath(e jsonx.Obj, path []string) any {
	var cur any = e
	for _, seg := range path {
		obj, ok := cur.(jsonx.Obj)
		if !ok {
			return nil
		}
		cur = nil
		for _, f := range obj {
			if strings.EqualFold(f.Name, seg) {
				cur = f.V
				break
			}
		}
	}
	return cur
}

// filterSchemas hold every property of an entity type (rendered from an empty
// entity), so a filter is validated even when the collection is empty.
var filterSchemas = map[string]jsonx.Obj{
	typeUser:  graphUser(&Config{Tenants: []Tenant{{}}}, &User{}),
	typeGroup: graphGroup(DirGroup{}),
}

// parseFilter compiles $filter for an entity type. Every failure is a
// Request_UnsupportedQuery, like any other query option this emulator refuses.
func parseFilter(src, odataType string) (filterExpr, *graphError) {
	toks, msg := lexFilter(src)
	if msg != "" {
		return nil, invalidFilter(msg)
	}
	p := &filterParser{toks: toks, odataType: odataType}
	f, gerr := p.or()
	if gerr != nil {
		return nil, gerr
	}
	if p.pos < len(p.toks) {
		return nil, invalidFilter("unexpected '" + p.toks[p.pos].text + "'")
	}
	return f, nil
}

func invalidFilter(msg string) *graphError {
	return unsupportedQuery("Invalid filter clause: " + msg + ".")
}

type filterTok struct {
	str  bool // a quoted string literal
	text string
}

func lexFilter(src string) ([]filterTok, string) {
	var out []filterTok
	rs := []rune(src)
	for i := 0; i < len(rs); {
		r := rs[i]
		switch {
		case unicode.IsSpace(r):
			i++
		case strings.ContainsRune("(),:", r):
			out = append(out, filterTok{text: string(r)})
			i++
		case r == '\'':
			var b strings.Builder
			i++
			closed := false
			for i < len(rs) {
				if rs[i] == '\'' {
					if i+1 < len(rs) && rs[i+1] == '\'' {
						b.WriteRune('\'')
						i += 2
						continue
					}
					closed = true
					i++
					break
				}
				b.WriteRune(rs[i])
				i++
			}
			if !closed {
				return nil, "unterminated string literal"
			}
			out = append(out, filterTok{str: true, text: b.String()})
		default:
			start := i
			for i < len(rs) && !unicode.IsSpace(rs[i]) && !strings.ContainsRune("(),:'", rs[i]) {
				i++
			}
			out = append(out, filterTok{text: string(rs[start:i])})
		}
	}
	if len(out) == 0 {
		return nil, "empty expression"
	}
	return out, ""
}

type filterParser struct {
	toks      []filterTok
	pos       int
	odataType string
}

func (p *filterParser) peek() (filterTok, bool) {
	if p.pos >= len(p.toks) {
		return filterTok{}, false
	}
	return p.toks[p.pos], true
}

// word consumes a case-insensitive keyword or punctuation token.
func (p *filterParser) word(w string) bool {
	if t, ok := p.peek(); ok && !t.str && strings.EqualFold(t.text, w) {
		p.pos++
		return true
	}
	return false
}

func (p *filterParser) expect(w string) *graphError {
	if !p.word(w) {
		t, _ := p.peek()
		return invalidFilter("expected '" + w + "' but found '" + t.text + "'")
	}
	return nil
}

func (p *filterParser) or() (filterExpr, *graphError) {
	first, gerr := p.and()
	if gerr != nil {
		return nil, gerr
	}
	out := filterOr{first}
	for p.word("or") {
		next, gerr := p.and()
		if gerr != nil {
			return nil, gerr
		}
		out = append(out, next)
	}
	if len(out) == 1 {
		return first, nil
	}
	return out, nil
}

func (p *filterParser) and() (filterExpr, *graphError) {
	first, gerr := p.unary()
	if gerr != nil {
		return nil, gerr
	}
	out := filterAnd{first}
	for p.word("and") {
		next, gerr := p.unary()
		if gerr != nil {
			return nil, gerr
		}
		out = append(out, next)
	}
	if len(out) == 1 {
		return first, nil
	}
	return out, nil
}

func (p *filterParser) unary() (filterExpr, *graphError) {
	if p.word("not") {
		inner, gerr := p.unary()
		if gerr != nil {
			return nil, gerr
		}
		return filterNot{inner}, nil
	}
	if p.word("(") {
		inner, gerr := p.or()
		if gerr != nil {
			return nil, gerr
		}
		if gerr := p.expect(")"); gerr != nil {
			return nil, gerr
		}
		return inner, nil
	}
	if p.word("startsWith") {
		return p.startsWith()
	}
	return p.comparison()
}

func (p *filterParser) startsWith() (filterExpr, *graphError) {
	if gerr := p.expect("("); gerr != nil {
		return nil, gerr
	}
	path, gerr := p.path()
	if gerr != nil {
		return nil, gerr
	}
	if gerr := p.expect(","); gerr != nil {
		return nil, gerr
	}
	t, ok := p.peek()
	if !ok || !t.str {
		return nil, invalidFilter("startsWith needs a string literal")
	}
	p.pos++
	if gerr := p.expect(")"); gerr != nil {
		return nil, gerr
	}
	return filterCmp{path: path, op: "startswith", lits: []any{t.text}}, nil
}

func (p *filterParser) comparison() (filterExpr, *graphError) {
	t, ok := p.peek()
	if ok && !t.str && len(t.text) > 4 && strings.EqualFold(t.text[len(t.text)-4:], "/any") {
		return p.any()
	}
	path, gerr := p.path()
	if gerr != nil {
		return nil, gerr
	}
	op, ok := p.peek()
	if !ok || op.str {
		return nil, invalidFilter("expected an operator after '" + strings.Join(path, "/") + "'")
	}
	p.pos++
	switch strings.ToLower(op.text) {
	case "eq", "ne":
		lit, gerr := p.literal()
		if gerr != nil {
			return nil, gerr
		}
		return filterCmp{path: path, op: strings.ToLower(op.text), lits: []any{lit}}, nil
	case "in":
		if gerr := p.expect("("); gerr != nil {
			return nil, gerr
		}
		var lits []any
		for {
			lit, gerr := p.literal()
			if gerr != nil {
				return nil, gerr
			}
			lits = append(lits, lit)
			if p.word(")") {
				return filterCmp{path: path, op: "in", lits: lits}, nil
			}
			if gerr := p.expect(","); gerr != nil {
				return nil, gerr
			}
		}
	}
	return nil, unsupportedQuery("The operator '" + op.text + "' is not supported by this emulator.")
}

// any parses path/any(x: x eq lit).
func (p *filterParser) any() (filterExpr, *graphError) {
	t, _ := p.peek()
	p.pos++
	path, gerr := p.resolve(t.text[:len(t.text)-4])
	if gerr != nil {
		return nil, gerr
	}
	if _, isArr := lookupPath(filterSchemas[p.odataType], path).(jsonx.Arr); !isArr {
		return nil, invalidFilter("any() needs a collection property")
	}
	if gerr := p.expect("("); gerr != nil {
		return nil, gerr
	}
	v, ok := p.peek()
	if !ok || v.str {
		return nil, invalidFilter("expected a lambda variable")
	}
	p.pos++
	if gerr := p.expect(":"); gerr != nil {
		return nil, gerr
	}
	if gerr := p.expect(v.text); gerr != nil {
		return nil, gerr
	}
	if !p.word("eq") {
		return nil, unsupportedQuery("Only 'eq' is supported inside any() by this emulator.")
	}
	lit, gerr := p.literal()
	if gerr != nil {
		return nil, gerr
	}
	if gerr := p.expect(")"); gerr != nil {
		return nil, gerr
	}
	return filterAny{path: path, lit: lit}, nil
}

func (p *filterParser) path() ([]string, *graphError) {
	t, ok := p.peek()
	if !ok || t.str || strings.ContainsAny(t.text, "(),:") {
		return nil, invalidFilter("expected a property name")
	}
	p.pos++
	return p.resolve(t.text)
}

// resolve checks a property path against the entity type's schema. Only a
// leaf value or a collection may be compared, never a whole complex object.
func (p *filterParser) resolve(raw string) ([]string, *graphError) {
	path := strings.Split(raw, "/")
	var cur any = filterSchemas[p.odataType]
	for _, seg := range path {
		obj, ok := cur.(jsonx.Obj)
		if !ok {
			return nil, unsupportedQuery("Could not find a property named '" + raw + "' on type '" + p.odataType + "'.")
		}
		found := false
		for _, f := range obj {
			if strings.EqualFold(f.Name, seg) && !strings.HasPrefix(f.Name, "@") {
				cur, found = f.V, true
				break
			}
		}
		if !found {
			return nil, unsupportedQuery("Could not find a property named '" + raw + "' on type '" + p.odataType + "'.")
		}
	}
	if _, isObj := cur.(jsonx.Obj); isObj {
		return nil, invalidFilter("'" + raw + "' is a complex property; filter on one of its members")
	}
	return path, nil
}

func (p *filterParser) literal() (any, *graphError) {
	t, ok := p.peek()
	if !ok {
		return nil, invalidFilter("expected a literal")
	}
	p.pos++
	if t.str {
		return t.text, nil
	}
	switch strings.ToLower(t.text) {
	case "null":
		return nil, nil
	case "true":
		return true, nil
	case "false":
		return false, nil
	}
	return nil, invalidFilter("expected a literal but found '" + t.text + "'")
}
