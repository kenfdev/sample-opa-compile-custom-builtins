package main

import (
	"context"
	"fmt"
	"github.com/open-policy-agent/opa/ast"
	"github.com/open-policy-agent/opa/rego"
	"github.com/open-policy-agent/opa/storage/inmem"
	"github.com/open-policy-agent/opa/types"
	"io/ioutil"
	"os"
)

var authzPolicyPath = "policy/authz.rego"
var authzQuery = "data.authz.allow"

func main() {
	ctx := context.Background()

	mods, err := initModules()
	if err != nil {
		fmt.Printf("failed to init modules: %v\n", err)
		os.Exit(1)
	}

	compiler, err := initCompiler(mods, map[string]*ast.Builtin{
		HelloBuiltin.Name: HelloBuiltin,
	})
	if err != nil {
		fmt.Printf("failed to compile modules: %v\n", err)
		os.Exit(1)
	}

	// create a simple store with hard coded policies
	store := inmem.NewFromObject(map[string]interface{}{
		"policies": map[string]interface{}{
			"alice": map[string]string{
				"effect": "allow",
			},
		},
	})

	q, err := initQuery()
	if err != nil {
		fmt.Printf("failed to parse query: %v\n", err)
		os.Exit(1)
	}

	helloFunc := rego.Function1(&rego.Function{
		Decl: HelloBuiltin.Decl,
		Name: HelloBuiltin.Name,
	}, HelloImpl)

	r := rego.New(rego.ParsedQuery(q),
		rego.Compiler(compiler),
		rego.Store(store),
		helloFunc,
	)

	pr, err := r.PartialResult(ctx)
	if err != nil {
		fmt.Printf("failed to create PartialResult: %+v\n", err)
		os.Exit(1)
	}

	input := map[string]interface{}{
		"user": "alice",
	}

	rs, err := pr.Rego(rego.Input(input)).Eval(ctx)
	if err != nil {
		fmt.Printf("failed to eval: %+v\n", err)
		os.Exit(1)
	}

	fmt.Printf("rs: %+v\n", rs)
}

func initModules() (map[string]*ast.Module, error) {
	b, err := ioutil.ReadFile("policy/authz.rego")
	if err != nil {
		return nil, err
	}

	m, err := ast.ParseModule(authzPolicyPath, string(b))
	if err != nil {
		return nil, err
	}

	mods := map[string]*ast.Module{
		authzPolicyPath: m,
	}

	return mods, nil
}

func initCompiler(mods map[string]*ast.Module, builtins map[string]*ast.Builtin) (*ast.Compiler, error) {
	compiler := ast.NewCompiler().WithBuiltins(builtins)
	compiler.Compile(mods)
	if compiler.Failed() {
		return nil, compiler.Errors
	}

	return compiler, nil
}

func initQuery() (ast.Body, error) {
	parsedQuery, err := ast.ParseBody(authzQuery)
	if err != nil {
		return nil, err
	}
	return parsedQuery, nil
}

var HelloBuiltin = &ast.Builtin{
	Name: "hello",
	Decl: types.NewFunction(types.Args(types.S), types.S),
}

func HelloImpl(bctx rego.BuiltinContext, a *ast.Term) (*ast.Term, error) {
	if str, ok := a.Value.(ast.String); ok {
		return ast.StringTerm("hello, " + string(str)), nil
	}
	return nil, nil
}
