package entra

import (
	"errors"
	"fmt"
	"regexp"
	"strings"
	"unicode"
)

// This file implements the subset of Entra dynamic membership rules this
// emulator evaluates (design: docs/entra/04-org-directory-design.md):
//
//	rule       := "Direct Reports for" "<manager oid>" | or
//	or         := and ("-or" and)*
//	and        := unary ("-and" unary)*
//	unary      := "-not" unary | "(" or ")" | user.<prop> op value
//	op         := -eq -ne -startsWith -notStartsWith -contains -notContains -in -notIn
//	value      := "string" | null | true | false | ["string", ...]
//
// Property names, operators and string values are case-insensitive, as in
// Entra. Device rules, -match and -any/-all are refused at parse time.

// userAttrs are the string user attributes rules read, keyed by lowercased
// name. accountEnabled, the one boolean, is handled separately.
var userAttrs = map[string]func(t *Tenant, u *User) string{
	"department":          func(_ *Tenant, u *User) string { return u.Department },
	"companyname":         func(_ *Tenant, u *User) string { return u.CompanyName },
	"employeeid":          func(_ *Tenant, u *User) string { return u.EmployeeID },
	"jobtitle":            func(_ *Tenant, u *User) string { return u.JobTitle },
	"officelocation":      func(_ *Tenant, u *User) string { return u.OfficeLocation },
	"displayname":         func(_ *Tenant, u *User) string { return u.Name },
	"mail":                func(_ *Tenant, u *User) string { return u.Email },
	"userprincipalname":   func(t *Tenant, u *User) string { return u.PrincipalName(t) },
	"extensionattribute1": func(_ *Tenant, u *User) string { return u.ExtensionAttributes.ExtensionAttribute1 },
	"extensionattribute2": func(_ *Tenant, u *User) string { return u.ExtensionAttributes.ExtensionAttribute2 },
	"extensionattribute3": func(_ *Tenant, u *User) string { return u.ExtensionAttributes.ExtensionAttribute3 },
}

// claimSources are the user attributes a claims mapping may emit, keyed by the
// lowercased "user.<attribute>" source name.
var claimSources = func() map[string]func(t *Tenant, u *User) string {
	out := map[string]func(t *Tenant, u *User) string{}
	for _, name := range []string{"department", "companyname", "employeeid", "jobtitle", "officelocation",
		"extensionattribute1", "extensionattribute2", "extensionattribute3"} {
		out["user."+name] = userAttrs[name]
	}
	return out
}()

// rule is a compiled membership rule.
type rule interface {
	match(c *Config, t *Tenant, u *User) bool
}

type orRule []rule
type andRule []rule
type notRule struct{ inner rule }

func (r orRule) match(c *Config, t *Tenant, u *User) bool {
	for _, x := range r {
		if x.match(c, t, u) {
			return true
		}
	}
	return false
}

func (r andRule) match(c *Config, t *Tenant, u *User) bool {
	for _, x := range r {
		if !x.match(c, t, u) {
			return false
		}
	}
	return true
}

func (r notRule) match(c *Config, t *Tenant, u *User) bool { return !r.inner.match(c, t, u) }

// directReportsRule is Entra's "Direct Reports for" rule: the users whose
// manager has the given object ID.
type directReportsRule struct{ managerOID string }

func (r directReportsRule) match(c *Config, _ *Tenant, u *User) bool {
	m := c.ManagerOf(u)
	return m != nil && m.OID == r.managerOID
}

// stringCompare compares a string attribute; an unset attribute is null.
type stringCompare struct {
	attr   func(t *Tenant, u *User) string
	op     string   // lowercased operator without the dash
	value  *string  // nil means null (only for eq/ne)
	values []string // -in / -notIn, lowercased
}

func (r stringCompare) match(_ *Config, t *Tenant, u *User) bool {
	got := r.attr(t, u)
	lower := strings.ToLower(got)
	switch r.op {
	case "eq", "ne":
		eq := got == ""
		if r.value != nil {
			eq = got != "" && strings.EqualFold(got, *r.value)
		}
		return eq == (r.op == "eq")
	case "startswith":
		return got != "" && strings.HasPrefix(lower, strings.ToLower(*r.value))
	case "notstartswith":
		return !strings.HasPrefix(lower, strings.ToLower(*r.value)) || got == ""
	case "contains":
		return got != "" && strings.Contains(lower, strings.ToLower(*r.value))
	case "notcontains":
		return !strings.Contains(lower, strings.ToLower(*r.value)) || got == ""
	}
	in := false
	for _, v := range r.values {
		if got != "" && lower == v {
			in = true
		}
	}
	return in == (r.op == "in")
}

// boolCompare compares accountEnabled.
type boolCompare struct {
	eq    bool
	value bool
}

func (r boolCompare) match(_ *Config, _ *Tenant, u *User) bool {
	return (u.Enabled() == r.value) == r.eq
}

var directReportsRE = regexp.MustCompile(`(?i)^direct\s+reports\s+for\s+"([^"]*)"$`)

// parseRule compiles a membership rule.
func parseRule(src string) (rule, error) {
	src = strings.TrimSpace(src)
	if src == "" {
		return nil, errors.New("empty rule")
	}
	if m := directReportsRE.FindStringSubmatch(src); m != nil {
		oid := strings.ToLower(strings.TrimSpace(m[1]))
		if !guidRE.MatchString(oid) {
			return nil, fmt.Errorf("Direct Reports for needs the manager's object ID (a GUID), got %q", m[1])
		}
		return directReportsRule{managerOID: oid}, nil
	}
	toks, err := lexRule(src)
	if err != nil {
		return nil, err
	}
	p := &ruleParser{toks: toks}
	r, err := p.or()
	if err != nil {
		return nil, err
	}
	if !p.done() {
		return nil, fmt.Errorf("unexpected %q", p.peek().text)
	}
	return r, nil
}

type ruleTokKind int

const (
	tokWord   ruleTokKind = iota // identifier, operator (-eq) or keyword (null)
	tokString                    // "quoted"
	tokPunct                     // ( ) [ ] ,
)

type ruleTok struct {
	kind ruleTokKind
	text string
}

func lexRule(src string) ([]ruleTok, error) {
	var out []ruleTok
	rs := []rune(src)
	for i := 0; i < len(rs); {
		r := rs[i]
		switch {
		case unicode.IsSpace(r):
			i++
		case strings.ContainsRune("()[],", r):
			out = append(out, ruleTok{tokPunct, string(r)})
			i++
		case r == '"':
			var b strings.Builder
			i++
			closed := false
			for i < len(rs) {
				if rs[i] == '\\' && i+1 < len(rs) {
					b.WriteRune(rs[i+1])
					i += 2
					continue
				}
				if rs[i] == '"' {
					closed = true
					i++
					break
				}
				b.WriteRune(rs[i])
				i++
			}
			if !closed {
				return nil, errors.New("unterminated string")
			}
			out = append(out, ruleTok{tokString, b.String()})
		default:
			start := i
			for i < len(rs) && !unicode.IsSpace(rs[i]) && !strings.ContainsRune("()[],\"", rs[i]) {
				i++
			}
			out = append(out, ruleTok{tokWord, string(rs[start:i])})
		}
	}
	return out, nil
}

type ruleParser struct {
	toks []ruleTok
	pos  int
}

func (p *ruleParser) done() bool { return p.pos >= len(p.toks) }

func (p *ruleParser) peek() ruleTok {
	if p.done() {
		return ruleTok{kind: tokPunct, text: ""}
	}
	return p.toks[p.pos]
}

// keyword reports and consumes a case-insensitive word token.
func (p *ruleParser) keyword(word string) bool {
	if t := p.peek(); t.kind == tokWord && strings.EqualFold(t.text, word) {
		p.pos++
		return true
	}
	return false
}

func (p *ruleParser) punct(s string) bool {
	if t := p.peek(); t.kind == tokPunct && t.text == s && !p.done() {
		p.pos++
		return true
	}
	return false
}

func (p *ruleParser) or() (rule, error) {
	first, err := p.and()
	if err != nil {
		return nil, err
	}
	out := orRule{first}
	for p.keyword("-or") {
		next, err := p.and()
		if err != nil {
			return nil, err
		}
		out = append(out, next)
	}
	if len(out) == 1 {
		return first, nil
	}
	return out, nil
}

func (p *ruleParser) and() (rule, error) {
	first, err := p.unary()
	if err != nil {
		return nil, err
	}
	out := andRule{first}
	for p.keyword("-and") {
		next, err := p.unary()
		if err != nil {
			return nil, err
		}
		out = append(out, next)
	}
	if len(out) == 1 {
		return first, nil
	}
	return out, nil
}

func (p *ruleParser) unary() (rule, error) {
	if p.keyword("-not") {
		inner, err := p.unary()
		if err != nil {
			return nil, err
		}
		return notRule{inner}, nil
	}
	if p.punct("(") {
		inner, err := p.or()
		if err != nil {
			return nil, err
		}
		if !p.punct(")") {
			return nil, errors.New("expected )")
		}
		return inner, nil
	}
	return p.comparison()
}

var ruleOps = map[string]bool{"eq": true, "ne": true, "startswith": true, "notstartswith": true,
	"contains": true, "notcontains": true, "in": true, "notin": true}

func (p *ruleParser) comparison() (rule, error) {
	prop := p.peek()
	if prop.kind != tokWord || p.done() {
		return nil, fmt.Errorf("expected a user property, got %q", prop.text)
	}
	p.pos++
	name, ok := strings.CutPrefix(strings.ToLower(prop.text), "user.")
	_, isString := userAttrs[name]
	if !ok || (!isString && name != "accountenabled") {
		return nil, fmt.Errorf("unsupported property %q", prop.text)
	}
	opTok := p.peek()
	if opTok.kind != tokWord || !strings.HasPrefix(opTok.text, "-") {
		return nil, fmt.Errorf("expected an operator after %s", prop.text)
	}
	p.pos++
	op := strings.ToLower(strings.TrimPrefix(opTok.text, "-"))
	if !ruleOps[op] {
		return nil, fmt.Errorf("unsupported operator %q", opTok.text)
	}
	if name == "accountenabled" {
		if op != "eq" && op != "ne" {
			return nil, fmt.Errorf("%s only supports -eq and -ne", prop.text)
		}
		v := p.peek()
		if v.kind != tokWord || (!strings.EqualFold(v.text, "true") && !strings.EqualFold(v.text, "false")) {
			return nil, fmt.Errorf("%s compares to true or false", prop.text)
		}
		p.pos++
		return boolCompare{eq: op == "eq", value: strings.EqualFold(v.text, "true")}, nil
	}
	cmp := stringCompare{attr: userAttrs[name], op: op}
	if op == "in" || op == "notin" {
		vals, err := p.array(opTok.text)
		if err != nil {
			return nil, err
		}
		cmp.values = vals
		return cmp, nil
	}
	v := p.peek()
	switch {
	case p.done():
		return nil, fmt.Errorf("expected a value after %s", opTok.text)
	case v.kind == tokString:
		s := v.text
		cmp.value = &s
	case v.kind == tokWord && strings.EqualFold(v.text, "null"):
		if op != "eq" && op != "ne" {
			return nil, fmt.Errorf("%s needs a string value", opTok.text)
		}
	default:
		return nil, fmt.Errorf("expected a value after %s, got %q", opTok.text, v.text)
	}
	p.pos++
	return cmp, nil
}

// array reads ["a", "b"], lowercasing the values for -in comparison.
func (p *ruleParser) array(op string) ([]string, error) {
	if !p.punct("[") {
		return nil, fmt.Errorf("%s needs an array value", op)
	}
	var out []string
	for {
		v := p.peek()
		if v.kind != tokString || p.done() {
			return nil, fmt.Errorf("%s array values must be strings", op)
		}
		p.pos++
		out = append(out, strings.ToLower(v.text))
		if p.punct("]") {
			return out, nil
		}
		if !p.punct(",") {
			return nil, fmt.Errorf("%s array: expected , or ]", op)
		}
	}
}
