package xcryptofork

import (
	"errors"
	"fmt"
	"go/ast"
	"go/format"
	"go/parser"
	"go/token"
	"io"
	"path/filepath"
	"strconv"
	"strings"

	"golang.org/x/tools/go/ast/astutil"
)

// XCryptoBackendProxyPath is the path within an x/crypto fork of the backend proxy.
var XCryptoBackendProxyPath = filepath.Join("internal", "backend")

// xCryptoBackendMapPrefix is the prefix for command comments. It would be nice
// to omit the " ", but the Go formatter adds it back in. (Sometimes? It does
// in VS Code. It doesn't seem like Go formatters should, though.)
const xCryptoBackendMapPrefix = "// xcrypto_backend_map:"

func commands(n ast.Node) []string {
	var cmds []string
	ast.Inspect(n, func(n ast.Node) bool {
		if n, ok := n.(*ast.Comment); !ok {
			return true
		} else if cmd, ok := strings.CutPrefix(n.Text, xCryptoBackendMapPrefix); !ok {
			return true
		} else {
			cmds = append(cmds, cmd)
		}
		return false
	})
	return cmds
}

// FindBackendFiles returns the Go files that appear to be backends in the
// given directory. Returns the parsed trees rather than only the filenames: we
// parsed the file to determine if it's a backend, and the parsed data is
// useful later.
func FindBackendFiles(dir string) ([]*BackendFile, error) {
	matches, err := filepath.Glob(filepath.Join(dir, "*.go"))
	if err != nil {
		return nil, err
	}
	var backends []*BackendFile
	for _, match := range matches {
		b, err := NewBackendFile(match)
		if err != nil {
			if errors.Is(err, errNotBackend) {
				continue
			}
			return nil, err
		}
		backends = append(backends, b)
	}
	return backends, nil
}

type FormattedWriterTo interface {
	Format(w io.Writer) error
}

var errNotBackend = errors.New("not a crypto backend file")

type BackendFile struct {
	// Filename is the absolute path to the original file.
	Filename   string
	Constraint string

	f    *ast.File
	fset *token.FileSet

	enabledDecl *ast.ValueSpec
}

func NewBackendFile(filename string) (*BackendFile, error) {
	b := &BackendFile{
		Filename: filename,
		fset:     token.NewFileSet(),
	}
	f, err := parser.ParseFile(b.fset, filename, nil, parser.ParseComments)
	if err != nil {
		return nil, err
	}
	b.f = f
	// Super simple heuristic that works for "crypto/internal/backend": does
	// the file define "Enabled"?
	enabledObj := f.Scope.Lookup("Enabled")
	if enabledObj == nil {
		return nil, errNotBackend
	}
	var ok bool
	if b.enabledDecl, ok = enabledObj.Decl.(*ast.ValueSpec); !ok {
		return nil, fmt.Errorf(
			"found Enabled symbol, but not a ValueSpec: %q defined at %v",
			enabledObj.Name, b.fset.Position(enabledObj.Pos()))
	}
	// Preserve the build constraint.
	for _, cg := range f.Comments {
		for _, c := range cg.List {
			if strings.HasPrefix(c.Text, "//go:build ") {
				b.Constraint = c.Text
				break
			}
		}
	}
	return b, nil
}

// APITrim changes b to include a placeholder API, following conventions that
// assume b is a "nobackend" crypto backend. The placeholder API is buildable,
// but panics if used.
func (b *BackendFile) APITrim() error {
	var err error
	localPackageType := make(map[string]*ast.TypeSpec)
	_ = astutil.Apply(b.f, func(c *astutil.Cursor) bool {
		switch n := (c.Node()).(type) {
		// Only look into top-level declarations, nothing else.
		case *ast.File, *ast.GenDecl:
			return true

		case *ast.TypeSpec:
			// Remove type names declared in this package and keep track of
			// them to remove any functions that use them in another pass.
			localPackageType[n.Name.Name] = n
			c.Delete()

		case *ast.ValueSpec:
			// Remove all var/const declarations other than Enabled.
			declaresEnabled := false
			for _, name := range n.Names {
				if name.Name == "Enabled" {
					declaresEnabled = true
				}
			}
			if !declaresEnabled {
				c.Delete()
			} else if len(n.Names) != 1 {
				err = fmt.Errorf(
					"declaration for Enabled %v includes multiple names",
					b.fset.Position(n.Pos()))
			}
			// We could detect "const RandReader = ..." and change it to
			// "var RandReader io.Reader". go:linkname supports mapping a var
			// to a const in this way. However, this is already accessible via
			// "crypto/rand" and there is no need to provide direct access.
			// So, simply leave it out.
		}
		return false
	}, func(c *astutil.Cursor) bool {
		switch n := (c.Node()).(type) {
		case *ast.GenDecl:
			// Removing a ValueSpec or TypeSpec could leave a node with zero
			// specs. format.Node fails if there are zero specs. Clean it up.
			if len(n.Specs) == 0 {
				c.Delete()
			}
		}
		return true
	})
	if err != nil {
		return err
	}
	_ = astutil.Apply(b.f, func(c *astutil.Cursor) bool {
		switch n := (c.Node()).(type) {
		case *ast.File:
			return true
		case *ast.FuncDecl:
			// Remove unexported functions and all methods.
			if !n.Name.IsExported() || n.Recv != nil {
				c.Delete()
				return false
			}
			var remove bool
			ast.Inspect(n.Type, func(tn ast.Node) bool {
				switch tn := tn.(type) {
				case *ast.Ident:
					if _, ok := localPackageType[tn.Name]; ok {
						remove = true
						return false
					}
				}
				return true
			})
			if remove {
				c.Delete()
			}
		}
		return false
	}, nil)
	return cleanImports(b.f)
}

// ProxyAPI creates a proxy for b implementing each var/func in the given api.
// If b is missing some part of api, it is skipped and recorded in the returned
// BackendProxy to be included in a comment by Format.
//
// If a func in b uses the "noescape" command, the proxy includes
// "//go:noescape" on that func.
func (b *BackendFile) ProxyAPI(api *BackendFile) (*BackendProxy, error) {
	p := &BackendProxy{
		backend: b,
		api:     api,
		f:       &ast.File{Name: b.f.Name},
		fset:    token.NewFileSet(),
	}

	// Keep track of the first err hit by each AST walk in this variable.
	// Note that walks don't necessarily stop immediately when "return false" is
	// used, so take care that an error isn't cleared out by a later iteration.
	var err error
	failFalse := func(walkErr error) bool {
		if err == nil && walkErr != nil {
			err = walkErr
		}
		return false
	}

	// Copy the imports that are used to define the API.
	// Ignore the imports used by b: those will include internal packages and
	// backend-specific packages that we don't have access to.
	ast.Inspect(api.f, func(n ast.Node) bool {
		switch n := n.(type) {
		case *ast.File:
			return true
		case *ast.GenDecl:
			if n.Tok == token.IMPORT {
				return true
			}
		case *ast.ImportSpec:
			var name string
			if n.Name != nil {
				name = n.Name.Name
			}
			path, err := strconv.Unquote(n.Path.Value)
			if err != nil {
				return failFalse(err)
			}
			astutil.AddNamedImport(p.fset, p.f, name, path)
		}
		return false
	})
	if err != nil {
		return nil, err
	}

	// Add unsafe import needed for go:linkname.
	astutil.AddNamedImport(p.fset, p.f, "_", "unsafe")

	// Add Enabled const.
	if len(b.enabledDecl.Values) != 1 {
		return nil, fmt.Errorf(
			"declaration for Enabled %v includes 0 or multiple values",
			b.fset.Position(b.enabledDecl.Pos()))
	}
	v, err := deepCopyExpression(b.enabledDecl.Values[0])
	if err != nil {
		return nil, err
	}
	p.f.Decls = append(p.f.Decls, &ast.GenDecl{
		Tok: token.CONST,
		Specs: []ast.Spec{
			&ast.ValueSpec{
				Names:  []*ast.Ident{{Name: "Enabled"}},
				Values: []ast.Expr{v},
			},
		},
	})

	// For each API, find it in b. If exists, generate linkname "proxy" func.
	ast.Inspect(api.f, func(n ast.Node) bool {
		switch n := n.(type) {
		case *ast.File:
			return true
		case *ast.FuncDecl:
			apiFnType, err := deepCopyExpression(n.Type)
			if err != nil {
				return failFalse(err)
			}
			// Find the corresponding func in b.
			o := b.f.Scope.Lookup(n.Name.Name)
			if o == nil {
				p.missing = append(p.missing, n)
				p.f.Decls = append(p.f.Decls,
					newPanicFunc(n, apiFnType, "not implemented by this backend"))
				return false
			}
			fn, ok := o.Decl.(*ast.FuncDecl)
			if !ok {
				return failFalse(fmt.Errorf(
					"found symbol, but not a function: %q defined at %v",
					n.Name.Name, api.fset.Position(n.Pos())))
			}
			comments := []*ast.Comment{
				{Text: "//go:linkname " + n.Name.Name + " crypto/internal/backend." + n.Name.Name},
			}
			for _, cmd := range commands(fn) {
				switch cmd {
				case "noescape":
					comments = append(comments, &ast.Comment{Text: "//go:noescape"})
				default:
					return failFalse(fmt.Errorf("unknown command %q (%v)", cmd, b.fset.Position(n.Pos())))
				}
			}
			proxyFnType, err := deepCopyExpression(fn.Type)
			if err != nil {
				return failFalse(err)
			}
			proxyFn := &ast.FuncDecl{
				// Don't use the original data: make sure the token position is
				// not copied. Including a non-zero position causes the
				// formatter to write the comment in strange locations within
				// the function declaration: it tries to reconcile specific
				// token positions vs. the zero position of the comment.
				Name: ast.NewIdent(n.Name.Name),
				Type: proxyFnType,
				Doc:  &ast.CommentGroup{List: comments},
			}
			p.f.Decls = append(p.f.Decls, proxyFn)
		}
		return false
	})
	if err != nil {
		return nil, err
	}

	if err := cleanImports(p.f); err != nil {
		return nil, err
	}
	return p, nil
}

func (b *BackendFile) Format(w io.Writer) error {
	io.WriteString(w, "// Generated code. DO NOT EDIT.\n\n")
	if b.Constraint != "" {
		io.WriteString(w, b.Constraint)
		io.WriteString(w, "\n\n")
	}
	return write(b.f, b.fset, w)
}

type BackendProxy struct {
	backend *BackendFile
	api     *BackendFile

	f    *ast.File
	fset *token.FileSet

	missing []*ast.FuncDecl
}

func (p *BackendProxy) Format(w io.Writer) error {
	io.WriteString(w, "// Generated code. DO NOT EDIT.\n\n")
	io.WriteString(w, "// This file implements a proxy that links into a specific crypto backend.\n\n")
	if p.backend.Constraint != "" {
		io.WriteString(w, p.backend.Constraint)
		io.WriteString(w, "\n\n")
	}
	if len(p.missing) > 0 {
		io.WriteString(w, "// The following functions defined in the API are not implemented by the backend and panic instead:\n//\n")
		for _, fn := range p.missing {
			io.WriteString(w, "//\t")
			io.WriteString(w, fn.Name.Name)
			io.WriteString(w, "\n")
		}
		io.WriteString(w, "\n")
	}
	return write(p.f, p.fset, w)
}

func write(f *ast.File, fset *token.FileSet, w io.Writer) error {
	// Force the printer to use the comments associated with the nodes by
	// clearing the cache-like (but not just a cache) Comments slice.
	f.Comments = nil
	return format.Node(w, fset, f)
}

func cleanImports(f *ast.File) error {
	var err error
	var cleanedImports []ast.Spec
	_ = astutil.Apply(f, func(c *astutil.Cursor) bool {
		switch n := (c.Node()).(type) {
		case *ast.GenDecl:
			// Support multiple import declarations. Import blocks can't be
			// nested, so simply reset the slice.
			if n.Tok == token.IMPORT {
				cleanedImports = cleanedImports[:0]
			}
		case *ast.ImportSpec:
			var p string
			if p, err = strconv.Unquote(n.Path.Value); err != nil {
				return false
			}
			if n.Name != nil && n.Name.Name == "_" || astutil.UsesImport(f, p) {
				// Reset the position to remove unnecessary newlines when
				// imports are omitted.
				n.Path.ValuePos = 0
				cleanedImports = append(cleanedImports, n)
			}
			return false
		}
		return true
	}, func(c *astutil.Cursor) bool {
		switch n := (c.Node()).(type) {
		case *ast.GenDecl:
			if n.Tok == token.IMPORT {
				n.Specs = cleanedImports
			}
		}
		return true
	})
	return nil
}

func newPanicFunc(n *ast.FuncDecl, fnType *ast.FuncType, message string) *ast.FuncDecl {
	return &ast.FuncDecl{
		Name: ast.NewIdent(n.Name.Name),
		Type: fnType,
		Doc: &ast.CommentGroup{
			List: []*ast.Comment{{Text: "// Not implemented by this backend."}},
		},
		Body: &ast.BlockStmt{
			List: []ast.Stmt{
				&ast.ExprStmt{
					X: &ast.CallExpr{
						Fun: &ast.Ident{Name: "panic"},
						Args: []ast.Expr{
							&ast.BasicLit{
								Kind:  token.STRING,
								Value: strconv.Quote(message),
							},
						},
					},
				},
			},
		},
	}
}

// Deep copy functions for the AST, but without copying token positions.

func deepCopyFieldList(src *ast.FieldList) (*ast.FieldList, error) {
	var dst ast.FieldList
	for _, x := range src.List {
		xCopy, err := deepCopyField(x)
		if err != nil {
			return nil, err
		}
		dst.List = append(dst.List, xCopy)
	}
	return &dst, nil
}

func deepCopyField(src *ast.Field) (*ast.Field, error) {
	var dst ast.Field
	for _, n := range src.Names {
		nCopy, err := deepCopyExpression(n)
		if err != nil {
			return nil, err
		}
		dst.Names = append(dst.Names, nCopy)
	}
	var err error
	dst.Type, err = deepCopyExpression(src.Type)
	if err != nil {
		return nil, err
	}
	return &dst, nil
}

func deepCopyExpression[T ast.Expr](src T) (T, error) {
	var err error
	var f func(ast.Expr) ast.Expr
	f = func(src ast.Expr) ast.Expr {
		if src == nil {
			return nil
		}
		switch src := src.(type) {

		case *ast.ArrayType:
			return &ast.ArrayType{
				Elt: f(src.Elt),
				Len: f(src.Len),
			}

		case *ast.FuncType:
			if src.TypeParams != nil {
				err = fmt.Errorf("unsupported type params %v", src.TypeParams)
				return nil
			}
			var ft ast.FuncType
			ft.Params, err = deepCopyFieldList(src.Params)
			if err != nil {
				return nil
			}
			ft.Results, err = deepCopyFieldList(src.Results)
			if err != nil {
				return nil
			}
			return &ft

		case *ast.Ident:
			return ast.NewIdent(src.Name)

		case *ast.SelectorExpr:
			return &ast.SelectorExpr{
				X:   f(src.X),
				Sel: f(src.Sel).(*ast.Ident),
			}

		case *ast.BasicLit:
			return &ast.BasicLit{
				Kind:  src.Kind,
				Value: src.Value,
			}

		case *ast.StarExpr:
			return &ast.StarExpr{
				X: f(src.X),
			}
		}
		err = fmt.Errorf("unsupported expression type %T", src)
		return nil
	}
	r := f(src)
	if err != nil {
		return *new(T), err
	}
	return r.(T), nil
}
