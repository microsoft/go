package mkcgo

import (
	"bufio"
	"errors"
	"fmt"
	"go/token"
	"io"
	"slices"
	"strings"
)

// Parse parses r and adds all symbols to src.
func (src *Source) Parse(r io.Reader) error {
	s := bufio.NewScanner(r)
	var inEnum bool
	for s.Scan() {
		line := trim(s.Text())
		// Process comments.
		if strings.Contains(line, "/*") || strings.Contains(line, "*/") {
			// Block comment.
			return errors.New("block comments are not supported")
		}
		comment, line := processComments(line)
		comment = trim(comment)
		if comment != "" {
			src.Comments = append(src.Comments, comment)
		}
		line = trim(line)
		if line == "" {
			// Skip empty lines.
			continue
		}
		if inEnum {
			if strings.HasPrefix(line, "};") {
				inEnum = false
				continue
			}
			if line, found := strings.CutPrefix(line, "} "); found {
				typeName := strings.TrimSuffix(line, ";")
				typeName, _ = normalizeParam(typeName, "")
				if err := src.addSymbol(typeName); err != nil {
					return err
				}
				enum := src.Enums[len(src.Enums)-1]
				enum.Type = typeName
				inEnum = false
				continue
			}
			if err := src.addEnum(line); err != nil {
				return fmt.Errorf("can't parse enum in line %q: %w", line, err)
			}
			continue
		}
		if strings.HasPrefix(line, "enum {") || strings.HasPrefix(line, "typedef enum {") {
			src.Enums = append(src.Enums, &Enum{})
			inEnum = true
			continue
		}

		// Process preprocessor directives.
		if v, found := strings.CutPrefix(line, "#"); found {
			if v, found = strings.CutPrefix(v, "include "); found {
				src.Includes = append(src.Includes, v)
			}
			// Skip all other preprocessor directives.
			continue
		}

		// Process typedefs.
		if v, found := strings.CutPrefix(line, "typedef "); found {
			if err := src.addTypeDef(v); err != nil {
				return fmt.Errorf("can't parse typedef in line %q: %w", line, err)
			}
			continue
		}

		// Process extern variables.
		if v, found := strings.CutPrefix(line, "extern "); found {
			if err := src.addExtern(v); err != nil {
				return fmt.Errorf("can't parse extern in line %q: %w", line, err)
			}
			continue
		}

		// Process function.
		if err := src.addFn(line); err != nil {
			return fmt.Errorf("can't parse function in line %q: %w", line, err)
		}
	}
	return s.Err()
}

func (src *Source) addSymbol(name string) error {
	if src.symbols == nil {
		src.symbols = make(map[string]struct{})
	}
	if _, ok := src.symbols[name]; ok {
		return fmt.Errorf("duplicate symbol %q", name)
	}
	src.symbols[name] = struct{}{}
	return nil
}

// addEnum parses string s and returns created enum definition Enum.
func (src *Source) addEnum(line string) error {
	line = strings.TrimSuffix(line, ",")
	split := strings.SplitN(line, "=", 2)
	if len(split) != 2 {
		return errors.New("can't extract enum value")
	}
	name, value := trim(split[0]), trim(split[1])
	if err := src.addSymbol(name); err != nil {
		return err
	}
	enum := src.Enums[len(src.Enums)-1]
	enum.Values = append(enum.Values, EnumValue{
		Name:  name,
		Value: value,
	})
	return nil
}

// addTypeDef parses string s and returns created type definition TypeDef.
// line should have the typedef prefix removed.
func (src *Source) addTypeDef(line string) error {
	after := strings.TrimSuffix(line, ";")
	idx := strings.LastIndex(after, " ")
	if idx < 0 {
		return errors.New("can't extract type name")
	}
	name, typ := normalizeParam(after[idx+1:], after[:idx])
	if err := src.addSymbol(name); err != nil {
		return err
	}
	src.TypeDefs = append(src.TypeDefs, &TypeDef{
		Name: name,
		Type: typ,
	})
	return nil
}

func (src *Source) addExtern(line string) error {
	line = strings.TrimSuffix(line, ";")
	var attrs Attrs
	var err error
	line, err = extractAttributes(line, &attrs)
	if err != nil {
		return fmt.Errorf("can't extract extern attributes: %w", err)
	}
	idx := strings.LastIndex(line, " ")
	if idx < 0 {
		return errors.New("can't extract type name")
	}
	name, typ := normalizeParam(line[idx+1:], line[:idx])
	if err := src.addSymbol(name); err != nil {
		return err
	}
	src.Externs = append(src.Externs, &Extern{
		Name:      name,
		Type:      typ,
		Framework: attrs.Framework,
		Static:    attrs.Static,
	})
	return nil
}

// addFn parses string s and return created function Fn.
func (src *Source) addFn(s string) error {
	s = strings.TrimSuffix(s, ";")
	var attrs Attrs
	s, err := extractAttributes(s, &attrs)
	if err != nil {
		return fmt.Errorf("can't extract function attributes: %w", err)
	}
	if attrs.VariadicTarget != "" {
		// Validate variadic target.
		idx := slices.IndexFunc(src.Funcs, func(f *Func) bool {
			return f.Name == attrs.VariadicTarget
		})
		if idx == -1 {
			return fmt.Errorf("variadic target not found in preceding code")
		}
		if !src.Funcs[idx].Variadic() {
			return fmt.Errorf("variadic target is not variadic")
		}
	}
	if s == "" {
		return errors.New("empty function signature")
	}
	// function name and args
	prefix, body, _, found := extractSection(s, "(", ")")
	if !found || prefix == "" {
		return errors.New("invalid signature")
	}
	nameIdx := strings.LastIndexByte(prefix, ' ')
	if nameIdx < 0 || nameIdx+1 >= len(prefix) {
		return errors.New("missing name")
	}
	params, err := extractParams(body)
	if err != nil {
		return err
	}
	name, ret := normalizeParam(prefix[nameIdx+1:], prefix[:nameIdx])
	if err := src.addSymbol(name); err != nil {
		return err
	}
	src.Funcs = append(src.Funcs, &Func{
		Name:   name,
		Ret:    ret,
		Attrs:  attrs,
		Params: params,
	})
	return nil
}

// normalizeParam normalizes parameter name and type.
func normalizeParam(name, typ string) (string, string) {
	name, typ = trim(name), trim(typ)
	// Remove leading asterisks from the name and add them to the type.
	for strings.HasPrefix(name, "*") {
		name = name[1:]
		typ += "*"
	}
	if token.IsKeyword(name) || name == "error" {
		name = "__" + name
	}
	// Remove duplicated spaces.
	for strings.Contains(typ, "  ") {
		typ = strings.ReplaceAll(typ, "  ", " ")
	}
	// Remove all spaces between the asterisks and the type.
	typ = strings.ReplaceAll(typ, " *", "*")
	return trim(name), trim(typ)
}

// trim returns s with leading and trailing spaces and tabs removed.
func trim(s string) string {
	return strings.Trim(s, " \t")
}

// extractSection extracts text out of string s starting after start
// and ending just before end. ok return value will indicate success,
// and prefix, body and suffix will contain correspondent parts of string s.
func extractSection(s string, start, end string) (prefix, body, suffix string, ok bool) {
	s = trim(s)
	if v, ok := strings.CutPrefix(s, start); ok {
		// no prefix
		body = v
	} else {
		a := strings.SplitN(s, start, 2)
		if len(a) != 2 {
			return "", "", s, false
		}
		prefix = a[0]
		body = a[1]
	}
	idxStart := strings.Index(body, start)
	idxEnd := strings.LastIndex(body, end)
	if idxEnd == -1 {
		// no end
		return "", "", s, false
	}
	needBalancing := idxStart != -1 && idxStart < idxEnd
	if !needBalancing {
		return prefix, trim(body[:idxEnd]), trim(body[idxEnd+len(end):]), true
	}
	depth := 1
	for i := range len(body) {
		if strings.HasPrefix(body[i:], start) {
			depth++
		} else if strings.HasPrefix(body[i:], end) {
			depth--
			if depth == 0 {
				suffix = body[i+len(end):]
				body = body[:i]
				ok = true
				break
			}
		}
	}
	return
}

// processComments removes comments from line and returns the result.
func processComments(line string) (comment, remmaining string) {
	// Remove line comments.
	if before, comment, found := strings.Cut(line, "//"); found {
		return comment, before
	}
	return "", line
}

// extractAttributes extracts mkcgo attributes from string s.
// The attributes format follows the GCC __attribute__ syntax as
// described in https://gcc.gnu.org/onlinedocs/gcc/Attribute-Syntax.html.
func extractAttributes(s string, fnAttrs *Attrs) (string, error) {
	// There can be spaces between __attribute__ and the opening parenthesis.
	prefix, body, found := strings.Cut(s, "__attribute__")
	if !found {
		return s, nil
	}
	_, body, suffix, found := extractSection(body, "((", "))")
	if !found {
		return "", errors.New("__attribute__ should be followed by double parentheses")
	}
	if body == "" {
		return trim(prefix + suffix), nil
	}
	for body != "" {
		// Attributes are separated by commas. Get the next attribute.
		// We can't just use strings.Split because the attribute argument
		// can contain commas.
		var name, args string
		idxComma := strings.IndexByte(body, ',')
		idxParen := strings.IndexByte(body, '(')
		if idxComma != -1 && (idxParen == -1 || idxComma < idxParen) {
			// The attribute has no arguments.
			name = body[:idxComma]
			body = body[idxComma+1:]
		} else if idxParen != -1 && (idxComma == -1 || idxComma > idxParen) {
			// The attribute has arguments, possibly with commas.
			name = body[:idxParen]
			_, args, body, found = extractSection(body[idxParen:], "(", ")")
			if !found {
				return "", errors.New("unbalanced parentheses")
			}
			body = trim(body)
			if len(body) > 0 && body[0] != ',' {
				return "", errors.New("parameters must be separated by commas")
			}
			body = strings.TrimPrefix(body, ",")
		} else if idxComma == -1 && idxParen == -1 {
			// The attribute has no arguments and is the last one.
			name = body
			body = ""
		}
		name, args = trim(name), trim(args)
		var handled bool
		for _, attr := range attributes {
			if name != attr.name {
				continue
			}
			var vargs []string
			if args != "" {
				vargs = strings.Split(args, ",")
				for i := range vargs {
					vargs[i] = trim(strings.Trim(vargs[i], `"`))
				}
			}
			if err := attr.handle(fnAttrs, vargs...); err != nil {
				return "", fmt.Errorf("error parsing attribute %s: %w", name, err)
			}
			handled = true
			break
		}
		if !handled {
			return "", errors.New("unknown mkcgo attribute: " + name)
		}
	}
	return trim(prefix + suffix), nil
}

// extractParams parses s to extract function parameters.
func extractParams(s string) ([]*Param, error) {
	s = trim(s)
	if s == "" {
		// No parameters, normalize to "void".
		return []*Param{{"void", ""}}, nil
	}
	a := strings.Split(s, ",")
	ps := make([]*Param, 0, len(a))
	for i := range a {
		s2 := trim(a[i])
		if s2 == "" {
			return nil, errors.New("empty parameter")
		}
		b := strings.LastIndexByte(s2, ' ')
		var name, typ string
		if b != -1 {
			name, typ = s2[b+1:], s2[:b]
		} else {
			typ = s2
		}
		name, typ = normalizeParam(name, typ)
		ps = append(ps, &Param{
			Name: name,
			Type: typ,
		})
	}
	return ps, nil
}
