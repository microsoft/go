package mkcgo_test

import (
	"fmt"
	"reflect"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/microsoft/go/pkg/openssl/internal/mkcgo"
)

func TestFuncVariadic(t *testing.T) {
	tests := []struct {
		name     string
		params   []*mkcgo.Param
		expected bool
	}{
		{
			name:     "No parameters",
			params:   []*mkcgo.Param{},
			expected: false,
		},
		{
			name: "Non-variadic parameters",
			params: []*mkcgo.Param{
				{Name: "param1", Type: "int"},
				{Name: "param2", Type: "string"},
			},
			expected: false,
		},
		{
			name: "Last parameter is variadic",
			params: []*mkcgo.Param{
				{Name: "param1", Type: "int"},
				{Name: "param2", Type: "..."},
			},
			expected: true,
		},
		{
			name: "Single variadic parameter",
			params: []*mkcgo.Param{
				{Name: "param1", Type: "..."},
			},
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fn := &mkcgo.Func{Params: tt.params}
			if got := fn.Variadic(); got != tt.expected {
				t.Errorf("Func.Variadic() = %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestSourceTags(t *testing.T) {
	tests := []struct {
		name  string
		funcs []*mkcgo.Func
		want  []string
	}{
		{
			name:  "No functions",
			funcs: []*mkcgo.Func{},
			want:  []string{""},
		},
		{
			name: "Functions with no tags",
			funcs: []*mkcgo.Func{
				{Name: "Func1", Attrs: mkcgo.Attrs{Tags: []mkcgo.TagAttr{}}},
				{Name: "Func2", Attrs: mkcgo.Attrs{Tags: []mkcgo.TagAttr{}}},
			},
			want: []string{""},
		},
		{
			name: "Functions with unique tags",
			funcs: []*mkcgo.Func{
				{Name: "Func1", Attrs: mkcgo.Attrs{Tags: []mkcgo.TagAttr{{Tag: "tag1"}}}},
				{Name: "Func2", Attrs: mkcgo.Attrs{Tags: []mkcgo.TagAttr{{Tag: "tag2"}}}},
			},
			want: []string{"", "tag1", "tag2"},
		},
		{
			name: "Functions with duplicate tags",
			funcs: []*mkcgo.Func{
				{Name: "Func1", Attrs: mkcgo.Attrs{Tags: []mkcgo.TagAttr{{Tag: "tag1"}}}},
				{Name: "Func2", Attrs: mkcgo.Attrs{Tags: []mkcgo.TagAttr{{Tag: "tag1"}, {Tag: "tag2"}}}},
			},
			want: []string{"", "tag1", "tag2"},
		},
		{
			name: "Functions with unsorted tags",
			funcs: []*mkcgo.Func{
				{Name: "Func1", Attrs: mkcgo.Attrs{Tags: []mkcgo.TagAttr{{Tag: "tag3"}}}},
				{Name: "Func2", Attrs: mkcgo.Attrs{Tags: []mkcgo.TagAttr{{Tag: "tag1"}, {Tag: "tag2"}}}},
			},
			want: []string{"", "tag1", "tag2", "tag3"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			src := &mkcgo.Source{Funcs: tt.funcs}
			got := src.Tags()
			if !slices.Equal(got, tt.want) {
				t.Errorf("Source.Tags() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestFuncImportName(t *testing.T) {
	tests := []struct {
		name           string
		variadicTarget string
		funcName       string
		want           string
	}{
		{
			name:           "No VariadicTarget",
			variadicTarget: "",
			funcName:       "TestFunc",
			want:           "TestFunc",
		},
		{
			name:           "With VariadicTarget",
			variadicTarget: "TargetFunc",
			funcName:       "TestFunc",
			want:           "TargetFunc",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fn := &mkcgo.Func{
				Attrs: mkcgo.Attrs{VariadicTarget: tt.variadicTarget},
				Name:  tt.funcName,
			}
			if got := fn.ImportName(); got != tt.want {
				t.Errorf("Func.ImportName() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestFuncString(t *testing.T) {
	tests := []struct {
		name     string
		function *mkcgo.Func
		want     string
	}{
		{
			name:     "Function with no return type and no parameters",
			function: &mkcgo.Func{Name: "TestFunc"},
			want:     "TestFunc()",
		},
		{
			name:     "Function with return type and no parameters",
			function: &mkcgo.Func{Name: "TestFunc", Ret: "int"},
			want:     "int TestFunc()",
		},
		{
			name:     "Function with parameters and no return type",
			function: &mkcgo.Func{Name: "TestFunc", Params: []*mkcgo.Param{{Type: "int", Name: "param1"}, {Type: "string", Name: "param2"}}},
			want:     "TestFunc(int param1, string param2)",
		},
		{
			name:     "Function with return type and parameters",
			function: &mkcgo.Func{Name: "TestFunc", Ret: "void", Params: []*mkcgo.Param{{Type: "int", Name: "param1"}, {Type: "float", Name: "param2"}}},
			want:     "void TestFunc(int param1, float param2)",
		},
		{
			name: "Function with attributes",
			function: &mkcgo.Func{Name: "TestFunc", Ret: "void", Params: []*mkcgo.Param{{Type: "int", Name: "param1"}},
				Attrs: mkcgo.Attrs{
					Tags:             []mkcgo.TagAttr{{Tag: "tag1"}, {Tag: "tag2", Name: "name"}},
					Optional:         true,
					NoError:          true,
					ErrCond:          "error_condition",
					NoEscape:         true,
					NoCallback:       true,
					NoCheckPtrParams: []string{"param1"},
					Framework:        mkcgo.Framework{Name: "CoreFoundation", Version: "A"},
				},
			},
			want: "void TestFunc(int param1) [{tag1 } {tag2 name}], optional, noerror, errcond(error_condition), noescape, nocallback, nocheckptr(param1), framework(CoreFoundation, A)",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.function.String()
			if got != tt.want {
				t.Errorf("Func.String() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestParse(t *testing.T) {
	tests := []struct {
		content string
		want    *mkcgo.Source
	}{
		{
			content: `
#include <stdlib.h>
#include <stdint.h>`,
			want: &mkcgo.Source{
				Includes: []string{"<stdlib.h>", "<stdint.h>"},
			},
		}, {
			content: `
// C0
// #include <string.h>`,
			want: &mkcgo.Source{
				Comments: []string{"C0", "#include <string.h>"},
			},
		}, {
			content: `
typedef void* TD0;
typedef const char* TD1;
typedef unsigned int* TD2;`,
			want: &mkcgo.Source{
				TypeDefs: []*mkcgo.TypeDef{
					{"TD0", "void*"},
					{"TD1", "const char*"},
					{"TD2", "unsigned int*"},
				},
			},
		}, {
			content: `
enum {
	E0 = 1,
	E1 = (1+1),
	E2 =(1+2),
};`,
			want: &mkcgo.Source{
				Enums: []*mkcgo.Enum{
					{
						Values: []mkcgo.EnumValue{
							{"E0", "1"},
							{"E1", "(1+1)"},
							{"E2", "(1+2)"},
						},
					},
				},
			},
		}, {
			content: `
void F0(void) __attribute__((tag("t0"),noerror,tag("t1","tn0")));
int F1(int p1) __attribute__((errcond("ec0"),  noescape,    nocallback, nocheckptr(p1)));
int * F2(int **p1, void  * p2);
int *F3(int p1, void***) __attribute__((optional));
unsigned   long F4(int func, int type, ...);
int* F5(float, double) __attribute__((variadic("F4")));
void F6() __attribute__(());`,
			want: &mkcgo.Source{
				Funcs: []*mkcgo.Func{
					{Name: "F0", Ret: "void", Params: []*mkcgo.Param{{"void", ""}}, Attrs: mkcgo.Attrs{Tags: []mkcgo.TagAttr{{Tag: "t0"}, {Tag: "t1", Name: "tn0"}}, NoError: true}},
					{Name: "F1", Ret: "int", Params: []*mkcgo.Param{{"int", "p1"}}, Attrs: mkcgo.Attrs{ErrCond: "ec0", NoEscape: true, NoCallback: true, NoCheckPtrParams: []string{"p1"}}},
					{Name: "F2", Ret: "int*", Params: []*mkcgo.Param{{"int**", "p1"}, {"void*", "p2"}}},
					{Name: "F3", Ret: "int*", Params: []*mkcgo.Param{{"int", "p1"}, {"void***", ""}}, Attrs: mkcgo.Attrs{Optional: true}},
					{Name: "F4", Ret: "unsigned long", Params: []*mkcgo.Param{{"int", "__func"}, {"int", "__type"}, {"...", ""}}},
					{Name: "F5", Ret: "int*", Params: []*mkcgo.Param{{"float", ""}, {"double", ""}}, Attrs: mkcgo.Attrs{VariadicTarget: "F4"}},
					{Name: "F6", Ret: "void", Params: []*mkcgo.Param{{"void", ""}}},
				},
			},
		},
	}
	for i, tt := range tests {
		// No need to specify a test name, the error message is enough to identify the test.
		t.Run(strconv.Itoa(i), func(t *testing.T) {
			var got mkcgo.Source
			if err := got.Parse(strings.NewReader(tt.content)); err != nil {
				t.Fatal(err)
			}
			testSlice(t, "Includes", got.Includes, tt.want.Includes)
			testSlice(t, "Comments", got.Comments, tt.want.Comments)
			testSlice(t, "TypeDefs", got.TypeDefs, tt.want.TypeDefs)
			testSlice(t, "Enums", got.Enums, tt.want.Enums)
			testSlice(t, "Funcs", got.Funcs, tt.want.Funcs)
		})
	}
}

func TestParseError(t *testing.T) {
	tests := []struct {
		content string
		want    string
	}{
		{
			content: `/**/`,
			want:    `block comments are not supported`,
		}, {
			content: "enum {\nE0 1,\n};",
			want:    `can't parse enum in line "E0 1,": can't extract enum value`,
		}, {
			content: `typedef T0;`,
			want:    `can't extract type name`,
		}, {
			content: `void foo(;`,
			want:    `invalid signature`,
		}, {
			content: `void;`,
			want:    `invalid signature`,
		}, {
			content: `void (void);`,
			want:    `missing name`,
		}, {
			content: `void foo(,);`,
			want:    `empty parameter`,
		}, {
			content: `void foo2(int a) __attribute__((variadic("foo")));`,
			want:    "variadic target not found in preceding code",
		}, {
			content: `
void foo();
void foo2(int a) __attribute__((variadic("foo")));
`, want: "variadic target is not variadic",
		}, {
			content: `void foo(void) __attribute__();`,
			want:    `can't extract function attributes: __attribute__ should be followed by double parentheses`,
		}, {
			content: `void foo(void) __attribute__;`,
			want:    `can't extract function attributes: __attribute__ should be followed by double parentheses`,
		}, {
			content: `void foo(void) __attribute__((tag("a")optional));`,
			want:    `can't extract function attributes: parameters must be separated by commas`,
		}, {
			content: `void foo(void) __attribute__((tag("a"());`,
			want:    `can't extract function attributes: unbalanced parentheses`,
		}, {
			content: `__attribute__((optional));`,
			want:    `empty function signature`,
		}, {
			content: `void foo(void) __attribute__((errcond("a"),noerror));`,
			want:    `can't extract function attributes: error parsing attribute noerror: not allowed with errcond attribute`,
		}, {
			content: `void foo(void) __attribute__((noerror,errcond("a")));`,
			want:    `can't extract function attributes: error parsing attribute errcond: not allowed with noerror attribute`,
		}, {
			content: `void foo(void) __attribute__((foo_bar));`,
			want:    `can't extract function attributes: unknown mkcgo attribute: foo_bar`,
		}, {
			content: `
enum {
	E0 = 0,
	E0 = 1,
};`,
			want: `duplicate symbol "E0"`,
		}, {
			content: `
enum {
	E1 = 0,
};
typedef void* E1;
`,
			want: `duplicate symbol "E1"`,
		}, {
			content: `
typedef void* E2;
void E2(void);
`,
			want: `duplicate symbol "E2"`,
		}, {
			content: `
void F1(void) __attribute__((framework("t1")));
`,
			want: `can't extract function attributes: error parsing attribute framework: requires 2 arguments`,
		},
	}
	for i, tt := range tests {
		// No need to specify a test name, the error message is enough to identify the test.
		t.Run(strconv.Itoa(i), func(t *testing.T) {
			var src mkcgo.Source
			err := src.Parse(strings.NewReader(tt.content))
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("want error %q to contain %q", tt.want, err)
			}
		})
	}
}

// testSlice checks that got and want are equal.
// If they are not, it reports an error with a detailed message.
func testSlice[S ~[]E, E comparable](t *testing.T, name string, got, want S) {
	t.Helper()
	if reflect.DeepEqual(got, want) {
		return
	}
	str := fmt.Sprintf("== %s ==\n", name)
	if len(got) != len(want) {
		str += fmt.Sprintf("len: got %d, want %d\n", len(got), len(want))
	}
	n := max(len(got), len(want))
	for i := range n {
		if i >= len(got) {
			str += fmt.Sprintf("[%d]:got nil, want {%v}\n", i, want[i])
		} else if i >= len(want) {
			str += fmt.Sprintf("[%d]:got {%v}, want nil\n", i, got[i])
		} else if !reflect.DeepEqual(got[i], want[i]) {
			str += fmt.Sprintf("[%d]:got {%v}, want {%v}\n", i, got[i], want[i])
		}
	}
	t.Error(str)
}
