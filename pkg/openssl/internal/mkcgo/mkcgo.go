// The mkcgo package provides a C header syntax parser.
// It supports just the necessary features to parse the OpenSSL symbols used in this project.
package mkcgo

import (
	"errors"
	"fmt"
	"slices"
	"strings"
)

// Source is a collection of type definitions and functions.
type Source struct {
	TypeDefs []*TypeDef
	Externs  []*Extern
	Enums    []*Enum
	Funcs    []*Func
	Comments []string // All line comments. Leading and trailing spaces are trimmed.
	Includes []string // All #include directives, without the #include prefix.

	symbols map[string]struct{} // All symbols defined in the source.
}

// TypeDef describes a type definition.
type TypeDef struct {
	Name string
	Type string
}

// Extern describes an extern variable.
type Extern struct {
	Name      string
	Type      string
	Framework Framework
	Static    bool
}

// Enum describes an enum block.
type Enum struct {
	Type   string
	Values []EnumValue
}

// EnumValue describes an enum definition.
type EnumValue struct {
	Name  string
	Value string
}

// Framework describes a framework
type Framework struct {
	Name    string
	Version string
}

// Attrs contains attributes of a C symbol.
type Attrs struct {
	Tags             []TagAttr
	VariadicTarget   string
	Optional         bool
	NoError          bool
	ErrCond          string
	NoEscape         bool
	NoCallback       bool
	NoCheckPtrParams []string
	Framework        Framework
	Static           bool
}

func (attrs *Attrs) String() string {
	var bld strings.Builder
	if len(attrs.Tags) != 0 {
		bld.Write([]byte(fmt.Sprintf("%s", attrs.Tags)))
	}
	if attrs.VariadicTarget != "" {
		bld.WriteString(", variadic(")
		bld.WriteString(attrs.VariadicTarget)
		bld.WriteByte(')')
	}
	if attrs.Optional {
		bld.WriteString(", optional")
	}
	if attrs.NoError {
		bld.WriteString(", noerror")
	}
	if attrs.ErrCond != "" {
		bld.WriteString(", errcond(")
		bld.WriteString(attrs.ErrCond)
		bld.WriteByte(')')
	}
	if attrs.NoEscape {
		bld.WriteString(", noescape")
	}
	if attrs.NoCallback {
		bld.WriteString(", nocallback")
	}
	if len(attrs.NoCheckPtrParams) != 0 {
		bld.WriteString(", nocheckptr(")
		for i, p := range attrs.NoCheckPtrParams {
			if i > 0 {
				bld.WriteString(", ")
			}
			bld.WriteString(p)
		}
		bld.WriteByte(')')
	}
	if len(attrs.Framework.Name) != 0 {
		bld.WriteString(", framework(")
		bld.WriteString(attrs.Framework.Name)
		bld.WriteString(", ")
		bld.WriteString(attrs.Framework.Version)
		bld.WriteByte(')')
	}
	return strings.TrimPrefix(bld.String(), ", ")
}

// Func describes a function.
type Func struct {
	Attrs
	Name   string
	Params []*Param
	Ret    string
}

// Variadic returns true if the ends with a variadic parameter.
func (f *Func) Variadic() bool {
	return len(f.Params) > 0 && f.Params[len(f.Params)-1].Variadic()
}

// ImportName returns the import name of the function.
func (f *Func) ImportName() string {
	if f.VariadicTarget != "" {
		return f.VariadicTarget
	}
	return f.Name
}

// String returns a string representation of the function,
// which is not necessarily valid Go nor C code.
func (f *Func) String() string {
	var bld strings.Builder
	if f.Ret != "" {
		bld.WriteString(f.Ret)
		bld.WriteByte(' ')
	}
	bld.WriteString(f.Name)
	bld.WriteByte('(')
	for i, p := range f.Params {
		if i > 0 {
			bld.WriteString(", ")
		}
		bld.WriteString(p.Type)
		if p.Name != "" {
			bld.WriteByte(' ')
			bld.WriteString(p.Name)
		}
	}
	bld.WriteString(")")
	if attrs := f.Attrs.String(); attrs != "" {
		bld.WriteByte(' ')
		bld.WriteString(attrs)
	}
	return bld.String()
}

// TagAttr is an attribute of a tag with an optional name.
type TagAttr struct {
	Tag  string
	Name string
}

// Param is a function parameter.
type Param struct {
	Type string
	Name string
}

func (p *Param) Variadic() bool {
	return p.Type == "..."
}

// Return is a function return value.
type Return struct {
	Name string
	Type string
}

func (src *Source) Tags() []string {
	tags := make([]string, 0, len(src.Funcs)+1)
	tags = append(tags, "") // default tag
	for _, fn := range src.Funcs {
		for _, tag := range fn.Tags {
			if !slices.Contains(tags, tag.Tag) {
				tags = append(tags, tag.Tag)
			}
		}
	}
	slices.Sort(tags)
	return tags
}

type attribute struct {
	name        string
	description string
	handle      func(*Attrs, ...string) error
}

var attributes = [...]attribute{
	{
		name:        "tag",
		description: "The function will be loaded together with other functions with the same tag. It can contain an optional name, which is the import name for the tag.",
		handle: func(opts *Attrs, s ...string) error {
			var name string
			if len(s) > 1 {
				name = s[1]
			}
			opts.Tags = append(opts.Tags, TagAttr{Tag: s[0], Name: name})
			return nil
		},
	},
	{
		name:        "variadic",
		description: "The function has variadic arguments, and its name is a custom wrapper for the actual C name, defined in this attribute.",
		handle: func(opts *Attrs, s ...string) error {
			opts.VariadicTarget = s[0]
			return nil
		},
	},
	{
		name:        "optional",
		description: "The function is optional",
		handle: func(opts *Attrs, s ...string) error {
			opts.Optional = true
			return nil
		},
	},
	{
		name:        "noerror",
		description: "The function does not return an error, and the program will panic if the function returns an error.",
		handle: func(opts *Attrs, s ...string) error {
			if opts.ErrCond != "" {
				return errors.New("not allowed with errcond attribute")
			}
			opts.NoError = true
			return nil
		},
	},
	{
		name:        "errcond",
		description: "The function returns an error if the C function returns a value that matches the condition in this attribute.",
		handle: func(opts *Attrs, s ...string) error {
			if opts.NoError {
				return errors.New("not allowed with noerror attribute")
			}
			opts.ErrCond = s[0]
			return nil
		},
	},
	{
		name:        "noescape",
		description: "The C function does not keep a copy of the Go pointer.",
		handle: func(opts *Attrs, s ...string) error {
			opts.NoEscape = true
			return nil
		},
	},
	{
		name:        "nocallback",
		description: "The C function does not call back into Go.",
		handle: func(opts *Attrs, s ...string) error {
			opts.NoCallback = true
			return nil
		},
	},
	{
		name:        "nocheckptr",
		description: "The parameter will be hidden from the Go compiler.",
		handle: func(opts *Attrs, s ...string) error {
			opts.NoCheckPtrParams = append(opts.NoCheckPtrParams, s[0])
			return nil
		},
	},
	{
		name:        "static",
		description: "Use static cgo import for this symbol.",
		handle: func(opts *Attrs, s ...string) error {
			opts.Static = true
			return nil
		},
	},
	{
		name:        "framework",
		description: "The function is part of a framework.",
		handle: func(opts *Attrs, s ...string) error {
			if len(s) != 2 {
				return errors.New("requires 2 arguments")
			}
			opts.Framework = Framework{Name: s[0], Version: s[1]}
			return nil
		},
	},
}
