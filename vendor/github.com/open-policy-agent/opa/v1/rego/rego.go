// Copyright 2017 The OPA Authors.  All rights reserved.
// Use of this source code is governed by an Apache2
// license that can be found in the LICENSE file.

// Package rego exposes high level APIs for evaluating Rego policies.
package rego

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"maps"
	"strings"
	"time"

	bundleUtils "github.com/open-policy-agent/opa/internal/bundle"
	"github.com/open-policy-agent/opa/internal/compiler/wasm"
	"github.com/open-policy-agent/opa/internal/future"
	"github.com/open-policy-agent/opa/internal/planner"
	"github.com/open-policy-agent/opa/internal/rego/opa"
	"github.com/open-policy-agent/opa/internal/wasm/encoding"
	"github.com/open-policy-agent/opa/v1/ast"
	"github.com/open-policy-agent/opa/v1/bundle"
	"github.com/open-policy-agent/opa/v1/ir"
	"github.com/open-policy-agent/opa/v1/loader"
	"github.com/open-policy-agent/opa/v1/metrics"
	"github.com/open-policy-agent/opa/v1/plugins"
	"github.com/open-policy-agent/opa/v1/resolver"
	"github.com/open-policy-agent/opa/v1/storage"
	"github.com/open-policy-agent/opa/v1/storage/inmem"
	"github.com/open-policy-agent/opa/v1/topdown"
	"github.com/open-policy-agent/opa/v1/topdown/builtins"
	"github.com/open-policy-agent/opa/v1/topdown/cache"
	"github.com/open-policy-agent/opa/v1/topdown/print"
	"github.com/open-policy-agent/opa/v1/tracing"
	"github.com/open-policy-agent/opa/v1/types"
	"github.com/open-policy-agent/opa/v1/util"
)

const (
	defaultPartialNamespace = "partial"
	wasmVarPrefix           = "^"
)

// nolint: deadcode,varcheck
const (
	targetWasm = "wasm"
	targetRego = "rego"
)

// CompileResult represents the result of compiling a Rego query, zero or more
// Rego modules, and arbitrary contextual data into an executable.
type CompileResult struct {
	Bytes []byte `json:"bytes"`
}

// PartialQueries contains the queries and support modules produced by partial
// evaluation.
type PartialQueries struct {
	Queries []ast.Body    `json:"queries,omitempty"`
	Support []*ast.Module `json:"modules,omitempty"`
}

// PartialResult represents the result of partial evaluation. The result can be
// used to generate a new query that can be run when inputs are known.
type PartialResult struct {
	compiler     *ast.Compiler
	store        storage.Store
	body         ast.Body
	builtinDecls map[string]*ast.Builtin
	builtinFuncs map[string]*topdown.Builtin
}

// Rego returns an object that can be evaluated to produce a query result.
func (pr PartialResult) Rego(options ...func(*Rego)) *Rego {
	options = append(options, Compiler(pr.compiler), Store(pr.store), ParsedQuery(pr.body))
	r := New(options...)

	// Propagate any custom builtins.
	maps.Copy(r.builtinDecls, pr.builtinDecls)
	maps.Copy(r.builtinFuncs, pr.builtinFuncs)
	return r
}

// preparedQuery is a wrapper around a Rego object which has pre-processed
// state stored on it. Once prepared there are a more limited number of actions
// that can be taken with it. It will, however, be able to evaluate faster since
// it will not have to re-parse or compile as much.
type preparedQuery struct {
	r   *Rego
	cfg *PrepareConfig
}

// EvalContext defines the set of options allowed to be set at evaluation
// time. Any other options will need to be set on a new Rego object.
type EvalContext struct {
	hasInput                    bool
	time                        time.Time
	seed                        io.Reader
	rawInput                    *any
	parsedInput                 ast.Value
	metrics                     metrics.Metrics
	txn                         storage.Transaction
	instrument                  bool
	instrumentation             *topdown.Instrumentation
	partialNamespace            string
	queryTracers                []topdown.QueryTracer
	compiledQuery               compiledQuery
	unknowns                    []string
	disableInlining             []ast.Ref
	nondeterministicBuiltins    bool
	parsedUnknowns              []*ast.Term
	indexing                    bool
	earlyExit                   bool
	interQueryBuiltinCache      cache.InterQueryCache
	interQueryBuiltinValueCache cache.InterQueryValueCache
	ndBuiltinCache              builtins.NDBCache
	resolvers                   []refResolver
	httpRoundTripper            topdown.CustomizeRoundTripper
	sortSets                    bool
	copyMaps                    bool
	printHook                   print.Hook
	capabilities                *ast.Capabilities
	strictBuiltinErrors         bool
	virtualCache                topdown.VirtualCache
	baseCache                   topdown.BaseCache
	tracing                     tracing.Options
	externalCancel              topdown.Cancel // Note(philip): If non-nil, the cancellation is handled outside of this package.
}

func (e *EvalContext) RawInput() *any {
	return e.rawInput
}

func (e *EvalContext) ParsedInput() ast.Value {
	return e.parsedInput
}

func (e *EvalContext) Time() time.Time {
	return e.time
}

func (e *EvalContext) Seed() io.Reader {
	return e.seed
}

func (e *EvalContext) InterQueryBuiltinCache() cache.InterQueryCache {
	return e.interQueryBuiltinCache
}

func (e *EvalContext) InterQueryBuiltinValueCache() cache.InterQueryValueCache {
	return e.interQueryBuiltinValueCache
}

func (e *EvalContext) PrintHook() print.Hook {
	return e.printHook
}

func (e *EvalContext) Metrics() metrics.Metrics {
	return e.metrics
}

func (e *EvalContext) StrictBuiltinErrors() bool {
	return e.strictBuiltinErrors
}

func (e *EvalContext) NDBCache() builtins.NDBCache {
	return e.ndBuiltinCache
}

func (e *EvalContext) CompiledQuery() ast.Body {
	return e.compiledQuery.query
}

func (e *EvalContext) Capabilities() *ast.Capabilities {
	return e.capabilities
}

func (e *EvalContext) Transaction() storage.Transaction {
	return e.txn
}

func (e *EvalContext) TracingOpts() tracing.Options {
	return e.tracing
}

func (e *EvalContext) ExternalCancel() topdown.Cancel {
	return e.externalCancel
}

func (e *EvalContext) QueryTracers() []topdown.QueryTracer {
	return e.queryTracers
}

// EvalOption defines a function to set an option on an EvalConfig
type EvalOption func(*EvalContext)

// EvalInput configures the input for a Prepared Query's evaluation
func EvalInput(input any) EvalOption {
	return func(e *EvalContext) {
		e.rawInput = &input
		e.hasInput = true
	}
}

// EvalParsedInput configures the input for a Prepared Query's evaluation
func EvalParsedInput(input ast.Value) EvalOption {
	return func(e *EvalContext) {
		e.parsedInput = input
		e.hasInput = true
	}
}

// EvalMetrics configures the metrics for a Prepared Query's evaluation
func EvalMetrics(metric metrics.Metrics) EvalOption {
	return func(e *EvalContext) {
		e.metrics = metric
	}
}

// EvalTransaction configures the Transaction for a Prepared Query's evaluation
func EvalTransaction(txn storage.Transaction) EvalOption {
	return func(e *EvalContext) {
		e.txn = txn
	}
}

// EvalInstrument enables or disables instrumenting for a Prepared Query's evaluation
func EvalInstrument(instrument bool) EvalOption {
	return func(e *EvalContext) {
		e.instrument = instrument
	}
}

// EvalTracer configures a tracer for a Prepared Query's evaluation
// Deprecated: Use EvalQueryTracer instead.
func EvalTracer(tracer topdown.Tracer) EvalOption {
	return func(e *EvalContext) {
		if tracer != nil {
			e.queryTracers = append(e.queryTracers, topdown.WrapLegacyTracer(tracer))
		}
	}
}

// EvalQueryTracer configures a tracer for a Prepared Query's evaluation
func EvalQueryTracer(tracer topdown.QueryTracer) EvalOption {
	return func(e *EvalContext) {
		if tracer != nil {
			e.queryTracers = append(e.queryTracers, tracer)
		}
	}
}

// EvalPartialNamespace returns an argument that sets the namespace to use for
// partial evaluation results. The namespace must be a valid package path
// component.
func EvalPartialNamespace(ns string) EvalOption {
	return func(e *EvalContext) {
		e.partialNamespace = ns
	}
}

// EvalUnknowns returns an argument that sets the values to treat as
// unknown during partial evaluation.
func EvalUnknowns(unknowns []string) EvalOption {
	return func(e *EvalContext) {
		e.unknowns = unknowns
	}
}

// EvalDisableInlining returns an argument that adds a set of paths to exclude from
// partial evaluation inlining.
func EvalDisableInlining(paths []ast.Ref) EvalOption {
	return func(e *EvalContext) {
		e.disableInlining = paths
	}
}

// EvalParsedUnknowns returns an argument that sets the values to treat
// as unknown during partial evaluation.
func EvalParsedUnknowns(unknowns []*ast.Term) EvalOption {
	return func(e *EvalContext) {
		e.parsedUnknowns = unknowns
	}
}

// EvalRuleIndexing will disable indexing optimizations for the
// evaluation. This should only be used when tracing in debug mode.
func EvalRuleIndexing(enabled bool) EvalOption {
	return func(e *EvalContext) {
		e.indexing = enabled
	}
}

// EvalEarlyExit will disable 'early exit' optimizations for the
// evaluation. This should only be used when tracing in debug mode.
func EvalEarlyExit(enabled bool) EvalOption {
	return func(e *EvalContext) {
		e.earlyExit = enabled
	}
}

// EvalTime sets the wall clock time to use during policy evaluation.
// time.now_ns() calls will return this value.
func EvalTime(x time.Time) EvalOption {
	return func(e *EvalContext) {
		e.time = x
	}
}

// EvalSeed sets a reader that will seed randomization required by built-in functions.
// If a seed is not provided crypto/rand.Reader is used.
func EvalSeed(r io.Reader) EvalOption {
	return func(e *EvalContext) {
		e.seed = r
	}
}

// EvalInterQueryBuiltinCache sets the inter-query cache that built-in functions can utilize
// during evaluation.
func EvalInterQueryBuiltinCache(c cache.InterQueryCache) EvalOption {
	return func(e *EvalContext) {
		e.interQueryBuiltinCache = c
	}
}

// EvalInterQueryBuiltinValueCache sets the inter-query value cache that built-in functions can utilize
// during evaluation.
func EvalInterQueryBuiltinValueCache(c cache.InterQueryValueCache) EvalOption {
	return func(e *EvalContext) {
		e.interQueryBuiltinValueCache = c
	}
}

// EvalNDBuiltinCache sets the non-deterministic builtin cache that built-in functions can
// use during evaluation.
func EvalNDBuiltinCache(c builtins.NDBCache) EvalOption {
	return func(e *EvalContext) {
		e.ndBuiltinCache = c
	}
}

// EvalResolver sets a Resolver for a specified ref path for this evaluation.
func EvalResolver(ref ast.Ref, r resolver.Resolver) EvalOption {
	return func(e *EvalContext) {
		e.resolvers = append(e.resolvers, refResolver{ref, r})
	}
}

// EvalHTTPRoundTripper allows customizing the http.RoundTripper for this evaluation.
func EvalHTTPRoundTripper(t topdown.CustomizeRoundTripper) EvalOption {
	return func(e *EvalContext) {
		e.httpRoundTripper = t
	}
}

// EvalSortSets causes the evaluator to sort sets before returning them as JSON arrays.
func EvalSortSets(yes bool) EvalOption {
	return func(e *EvalContext) {
		e.sortSets = yes
	}
}

// EvalCopyMaps causes the evaluator to copy `map[string]any`s before returning them.
func EvalCopyMaps(yes bool) EvalOption {
	return func(e *EvalContext) {
		e.copyMaps = yes
	}
}

// EvalPrintHook sets the object to use for handling print statement outputs.
func EvalPrintHook(ph print.Hook) EvalOption {
	return func(e *EvalContext) {
		e.printHook = ph
	}
}

// EvalVirtualCache sets the topdown.VirtualCache to use for evaluation.
// This is optional, and if not set, the default cache is used.
func EvalVirtualCache(vc topdown.VirtualCache) EvalOption {
	return func(e *EvalContext) {
		e.virtualCache = vc
	}
}

// EvalBaseCache sets the topdown.BaseCache to use for evaluation.
// This is optional, and if not set, the default cache is used.
func EvalBaseCache(bc topdown.BaseCache) EvalOption {
	return func(e *EvalContext) {
		e.baseCache = bc
	}
}

// EvalNondeterministicBuiltins causes non-deterministic builtins to be evalued
// during partial evaluation. This is needed to pull in external data, or validate
// a JWT, during PE, so that the result informs what queries are returned.
func EvalNondeterministicBuiltins(yes bool) EvalOption {
	return func(e *EvalContext) {
		e.nondeterministicBuiltins = yes
	}
}

// EvalExternalCancel sets an external topdown.Cancel for the interpreter to use
// for cancellation. This is useful for batch-evaluation of many rego queries.
func EvalExternalCancel(ec topdown.Cancel) EvalOption {
	return func(e *EvalContext) {
		e.externalCancel = ec
	}
}

func (pq preparedQuery) Modules() map[string]*ast.Module {
	mods := make(map[string]*ast.Module)

	maps.Copy(mods, pq.r.parsedModules)

	for _, b := range pq.r.bundles {
		for _, mod := range b.Modules {
			mods[mod.Path] = mod.Parsed
		}
	}

	return mods
}

// newEvalContext creates a new EvalContext overlaying any EvalOptions over top
// the Rego object on the preparedQuery. The returned function should be called
// once the evaluation is complete to close any transactions that might have
// been opened.
func (pq preparedQuery) newEvalContext(ctx context.Context, options []EvalOption) (*EvalContext, func(context.Context), error) {
	ectx := &EvalContext{
		hasInput:                 false,
		rawInput:                 nil,
		parsedInput:              nil,
		metrics:                  nil,
		txn:                      nil,
		instrument:               false,
		instrumentation:          nil,
		partialNamespace:         pq.r.partialNamespace,
		queryTracers:             nil,
		unknowns:                 pq.r.unknowns,
		parsedUnknowns:           pq.r.parsedUnknowns,
		nondeterministicBuiltins: pq.r.nondeterministicBuiltins,
		compiledQuery:            compiledQuery{},
		indexing:                 true,
		earlyExit:                true,
		resolvers:                pq.r.resolvers,
		printHook:                pq.r.printHook,
		capabilities:             pq.r.capabilities,
		strictBuiltinErrors:      pq.r.strictBuiltinErrors,
		tracing:                  pq.r.distributedTracingOpts,
	}

	for _, o := range options {
		o(ectx)
	}

	if ectx.metrics == nil {
		ectx.metrics = metrics.New()
	}

	if ectx.instrument {
		ectx.instrumentation = topdown.NewInstrumentation(ectx.metrics)
	}

	// Default to an empty "finish" function
	finishFunc := func(context.Context) {}

	var err error
	ectx.disableInlining, err = parseStringsToRefs(pq.r.disableInlining)
	if err != nil {
		return nil, finishFunc, err
	}

	if ectx.txn == nil {
		ectx.txn, err = pq.r.store.NewTransaction(ctx)
		if err != nil {
			return nil, finishFunc, err
		}
		finishFunc = func(ctx context.Context) {
			pq.r.store.Abort(ctx, ectx.txn)
		}
	}

	// If we didn't get an input specified in the Eval options
	// then fall back to the Rego object's input fields.
	if !ectx.hasInput {
		ectx.rawInput = pq.r.rawInput
		ectx.parsedInput = pq.r.parsedInput
	}

	if ectx.parsedInput == nil {
		if ectx.rawInput == nil {
			// Fall back to the original Rego objects input if none was specified
			// Note that it could still be nil
			ectx.rawInput = pq.r.rawInput
		}

		if pq.r.targetPlugin(pq.r.target) == nil && // no plugin claims this target
			pq.r.target != targetWasm {
			ectx.parsedInput, err = pq.r.parseRawInput(ectx.rawInput, ectx.metrics)
			if err != nil {
				return nil, finishFunc, err
			}
		}
	}

	return ectx, finishFunc, nil
}

// PreparedEvalQuery holds the prepared Rego state that has been pre-processed
// for subsequent evaluations.
type PreparedEvalQuery struct {
	preparedQuery
}

// Eval evaluates this PartialResult's Rego object with additional eval options
// and returns a ResultSet.
// If options are provided they will override the original Rego options respective value.
// The original Rego object transaction will *not* be re-used. A new transaction will be opened
// if one is not provided with an EvalOption.
func (pq PreparedEvalQuery) Eval(ctx context.Context, options ...EvalOption) (ResultSet, error) {
	ectx, finish, err := pq.newEvalContext(ctx, options)
	if err != nil {
		return nil, err
	}
	defer finish(ctx)

	ectx.compiledQuery = pq.r.compiledQueries[evalQueryType]

	return pq.r.eval(ctx, ectx)
}

// PreparedPartialQuery holds the prepared Rego state that has been pre-processed
// for partial evaluations.
type PreparedPartialQuery struct {
	preparedQuery
}

// Partial runs partial evaluation on the prepared query and returns the result.
// The original Rego object transaction will *not* be re-used. A new transaction will be opened
// if one is not provided with an EvalOption.
func (pq PreparedPartialQuery) Partial(ctx context.Context, options ...EvalOption) (*PartialQueries, error) {
	ectx, finish, err := pq.newEvalContext(ctx, options)
	if err != nil {
		return nil, err
	}
	defer finish(ctx)

	ectx.compiledQuery = pq.r.compiledQueries[partialQueryType]

	return pq.r.partial(ctx, ectx)
}

// Errors represents a collection of errors returned when evaluating Rego.
type Errors []error

func (errs Errors) Error() string {
	if len(errs) == 0 {
		return "no error"
	}
	if len(errs) == 1 {
		return fmt.Sprintf("1 error occurred: %v", errs[0].Error())
	}
	buf := []string{fmt.Sprintf("%v errors occurred", len(errs))}
	for _, err := range errs {
		buf = append(buf, err.Error())
	}
	return strings.Join(buf, "\n")
}

var errPartialEvaluationNotEffective = errors.New("partial evaluation not effective")

// IsPartialEvaluationNotEffectiveErr returns true if err is an error returned by
// this package to indicate that partial evaluation was ineffective.
func IsPartialEvaluationNotEffectiveErr(err error) bool {
	errs, ok := err.(Errors)
	if !ok {
		return false
	}
	return len(errs) == 1 && errs[0] == errPartialEvaluationNotEffective
}

type compiledQuery struct {
	query    ast.Body
	compiler ast.QueryCompiler
}

type queryType int

// Define a query type for each of the top level Rego
// API's that compile queries differently.
const (
	evalQueryType queryType = iota
	partialResultQueryType
	partialQueryType
	compileQueryType
)

type loadPaths struct {
	paths  []string
	filter loader.Filter
}

// Rego constructs a query and can be evaluated to obtain results.
type Rego struct {
	query                       string
	parsedQuery                 ast.Body
	compiledQueries             map[queryType]compiledQuery
	pkg                         string
	parsedPackage               *ast.Package
	imports                     []string
	parsedImports               []*ast.Import
	rawInput                    *any
	parsedInput                 ast.Value
	unknowns                    []string
	parsedUnknowns              []*ast.Term
	disableInlining             []string
	shallowInlining             bool
	nondeterministicBuiltins    bool
	skipPartialNamespace        bool
	partialNamespace            string
	modules                     []rawModule
	parsedModules               map[string]*ast.Module
	compiler                    *ast.Compiler
	store                       storage.Store
	ownStore                    bool
	ownStoreReadAst             bool
	txn                         storage.Transaction
	metrics                     metrics.Metrics
	queryTracers                []topdown.QueryTracer
	tracebuf                    *topdown.BufferTracer
	trace                       bool
	instrumentation             *topdown.Instrumentation
	instrument                  bool
	capture                     map[*ast.Expr]ast.Var // map exprs to generated capture vars
	termVarID                   int
	dump                        io.Writer
	runtime                     *ast.Term
	time                        time.Time
	seed                        io.Reader
	capabilities                *ast.Capabilities
	builtinDecls                map[string]*ast.Builtin
	builtinFuncs                map[string]*topdown.Builtin
	unsafeBuiltins              map[string]struct{}
	loadPaths                   loadPaths
	bundlePaths                 []string
	bundles                     map[string]*bundle.Bundle
	skipBundleVerification      bool
	bundleActivationPlugin      string
	enableBundleLazyLoadingMode bool
	interQueryBuiltinCache      cache.InterQueryCache
	interQueryBuiltinValueCache cache.InterQueryValueCache
	ndBuiltinCache              builtins.NDBCache
	strictBuiltinErrors         bool
	builtinErrorList            *[]topdown.Error
	resolvers                   []refResolver
	schemaSet                   *ast.SchemaSet
	target                      string // target type (wasm, rego, etc.)
	opa                         opa.EvalEngine
	generateJSON                func(*ast.Term, *EvalContext) (any, error)
	printHook                   print.Hook
	enablePrintStatements       bool
	distributedTracingOpts      tracing.Options
	strict                      bool
	pluginMgr                   *plugins.Manager
	plugins                     []TargetPlugin
	targetPrepState             TargetPluginEval
	regoVersion                 ast.RegoVersion
	compilerHook                func(*ast.Compiler)
	evalMode                    *ast.CompilerEvalMode
}

func (r *Rego) RegoVersion() ast.RegoVersion {
	return r.regoVersion
}

// Function represents a built-in function that is callable in Rego.
type Function struct {
	Name             string
	Description      string
	Decl             *types.Function
	Memoize          bool
	Nondeterministic bool
}

// BuiltinContext contains additional attributes from the evaluator that
// built-in functions can use, e.g., the request context.Context, caches, etc.
type BuiltinContext = topdown.BuiltinContext

type (
	// Builtin1 defines a built-in function that accepts 1 argument.
	Builtin1 func(bctx BuiltinContext, op1 *ast.Term) (*ast.Term, error)

	// Builtin2 defines a built-in function that accepts 2 arguments.
	Builtin2 func(bctx BuiltinContext, op1, op2 *ast.Term) (*ast.Term, error)

	// Builtin3 defines a built-in function that accepts 3 argument.
	Builtin3 func(bctx BuiltinContext, op1, op2, op3 *ast.Term) (*ast.Term, error)

	// Builtin4 defines a built-in function that accepts 4 argument.
	Builtin4 func(bctx BuiltinContext, op1, op2, op3, op4 *ast.Term) (*ast.Term, error)

	// BuiltinDyn defines a built-in function  that accepts a list of arguments.
	BuiltinDyn func(bctx BuiltinContext, terms []*ast.Term) (*ast.Term, error)
)

// RegisterBuiltin1 adds a built-in function globally inside the OPA runtime.
func RegisterBuiltin1(decl *Function, impl Builtin1) {
	ast.RegisterBuiltin(&ast.Builtin{
		Name:             decl.Name,
		Description:      decl.Description,
		Decl:             decl.Decl,
		Nondeterministic: decl.Nondeterministic,
	})
	topdown.RegisterBuiltinFunc(decl.Name, func(bctx BuiltinContext, terms []*ast.Term, iter func(*ast.Term) error) error {
		result, err := memoize(decl, bctx, terms, func() (*ast.Term, error) { return impl(bctx, terms[0]) })
		return finishFunction(decl.Name, bctx, result, err, iter)
	})
}

// RegisterBuiltin2 adds a built-in function globally inside the OPA runtime.
func RegisterBuiltin2(decl *Function, impl Builtin2) {
	ast.RegisterBuiltin(&ast.Builtin{
		Name:             decl.Name,
		Description:      decl.Description,
		Decl:             decl.Decl,
		Nondeterministic: decl.Nondeterministic,
	})
	topdown.RegisterBuiltinFunc(decl.Name, func(bctx BuiltinContext, terms []*ast.Term, iter func(*ast.Term) error) error {
		result, err := memoize(decl, bctx, terms, func() (*ast.Term, error) { return impl(bctx, terms[0], terms[1]) })
		return finishFunction(decl.Name, bctx, result, err, iter)
	})
}

// RegisterBuiltin3 adds a built-in function globally inside the OPA runtime.
func RegisterBuiltin3(decl *Function, impl Builtin3) {
	ast.RegisterBuiltin(&ast.Builtin{
		Name:             decl.Name,
		Description:      decl.Description,
		Decl:             decl.Decl,
		Nondeterministic: decl.Nondeterministic,
	})
	topdown.RegisterBuiltinFunc(decl.Name, func(bctx BuiltinContext, terms []*ast.Term, iter func(*ast.Term) error) error {
		result, err := memoize(decl, bctx, terms, func() (*ast.Term, error) { return impl(bctx, terms[0], terms[1], terms[2]) })
		return finishFunction(decl.Name, bctx, result, err, iter)
	})
}

// RegisterBuiltin4 adds a built-in function globally inside the OPA runtime.
func RegisterBuiltin4(decl *Function, impl Builtin4) {
	ast.RegisterBuiltin(&ast.Builtin{
		Name:             decl.Name,
		Description:      decl.Description,
		Decl:             decl.Decl,
		Nondeterministic: decl.Nondeterministic,
	})
	topdown.RegisterBuiltinFunc(decl.Name, func(bctx BuiltinContext, terms []*ast.Term, iter func(*ast.Term) error) error {
		result, err := memoize(decl, bctx, terms, func() (*ast.Term, error) { return impl(bctx, terms[0], terms[1], terms[2], terms[3]) })
		return finishFunction(decl.Name, bctx, result, err, iter)
	})
}

// RegisterBuiltinDyn adds a built-in function globally inside the OPA runtime.
func RegisterBuiltinDyn(decl *Function, impl BuiltinDyn) {
	ast.RegisterBuiltin(&ast.Builtin{
		Name:             decl.Name,
		Description:      decl.Description,
		Decl:             decl.Decl,
		Nondeterministic: decl.Nondeterministic,
	})
	topdown.RegisterBuiltinFunc(decl.Name, func(bctx BuiltinContext, terms []*ast.Term, iter func(*ast.Term) error) error {
		result, err := memoize(decl, bctx, terms, func() (*ast.Term, error) { return impl(bctx, terms) })
		return finishFunction(decl.Name, bctx, result, err, iter)
	})
}

// Function1 returns an option that adds a built-in function to the Rego object.
func Function1(decl *Function, f Builtin1) func(*Rego) {
	return newFunction(decl, func(bctx BuiltinContext, terms []*ast.Term, iter func(*ast.Term) error) error {
		result, err := memoize(decl, bctx, terms, func() (*ast.Term, error) { return f(bctx, terms[0]) })
		return finishFunction(decl.Name, bctx, result, err, iter)
	})
}

// Function2 returns an option that adds a built-in function to the Rego object.
func Function2(decl *Function, f Builtin2) func(*Rego) {
	return newFunction(decl, func(bctx BuiltinContext, terms []*ast.Term, iter func(*ast.Term) error) error {
		result, err := memoize(decl, bctx, terms, func() (*ast.Term, error) { return f(bctx, terms[0], terms[1]) })
		return finishFunction(decl.Name, bctx, result, err, iter)
	})
}

// Function3 returns an option that adds a built-in function to the Rego object.
func Function3(decl *Function, f Builtin3) func(*Rego) {
	return newFunction(decl, func(bctx BuiltinContext, terms []*ast.Term, iter func(*ast.Term) error) error {
		result, err := memoize(decl, bctx, terms, func() (*ast.Term, error) { return f(bctx, terms[0], terms[1], terms[2]) })
		return finishFunction(decl.Name, bctx, result, err, iter)
	})
}

// Function4 returns an option that adds a built-in function to the Rego object.
func Function4(decl *Function, f Builtin4) func(*Rego) {
	return newFunction(decl, func(bctx BuiltinContext, terms []*ast.Term, iter func(*ast.Term) error) error {
		result, err := memoize(decl, bctx, terms, func() (*ast.Term, error) { return f(bctx, terms[0], terms[1], terms[2], terms[3]) })
		return finishFunction(decl.Name, bctx, result, err, iter)
	})
}

// FunctionDyn returns an option that adds a built-in function to the Rego object.
func FunctionDyn(decl *Function, f BuiltinDyn) func(*Rego) {
	return newFunction(decl, func(bctx BuiltinContext, terms []*ast.Term, iter func(*ast.Term) error) error {
		result, err := memoize(decl, bctx, terms, func() (*ast.Term, error) { return f(bctx, terms) })
		return finishFunction(decl.Name, bctx, result, err, iter)
	})
}

// FunctionDecl returns an option that adds a custom-built-in function
// __declaration__. NO implementation is provided. This is used for
// non-interpreter execution envs (e.g., Wasm).
func FunctionDecl(decl *Function) func(*Rego) {
	return newDecl(decl)
}

func newDecl(decl *Function) func(*Rego) {
	return func(r *Rego) {
		r.builtinDecls[decl.Name] = &ast.Builtin{
			Name: decl.Name,
			Decl: decl.Decl,
		}
	}
}

type memo struct {
	term *ast.Term
	err  error
}

type memokey string

func memoize(decl *Function, bctx BuiltinContext, terms []*ast.Term, ifEmpty func() (*ast.Term, error)) (*ast.Term, error) {

	if !decl.Memoize {
		return ifEmpty()
	}

	// NOTE(tsandall): we assume memoization is applied to infrequent built-in
	// calls that do things like fetch data from remote locations. As such,
	// converting the terms to strings is acceptable for now.
	var b strings.Builder
	if _, err := b.WriteString(decl.Name); err != nil {
		return nil, err
	}

	// The term slice _may_ include an output term depending on how the caller
	// referred to the built-in function. Only use the arguments as the cache
	// key. Unification ensures we don't get false positive matches.
	for i := range decl.Decl.Arity() {
		if _, err := b.WriteString(terms[i].String()); err != nil {
			return nil, err
		}
	}

	key := memokey(b.String())
	hit, ok := bctx.Cache.Get(key)
	var m memo
	if ok {
		m = hit.(memo)
	} else {
		m.term, m.err = ifEmpty()
		bctx.Cache.Put(key, m)
	}

	return m.term, m.err
}

// Dump returns an argument that sets the writer to dump debugging information to.
func Dump(w io.Writer) func(r *Rego) {
	return func(r *Rego) {
		r.dump = w
	}
}

// Query returns an argument that sets the Rego query.
func Query(q string) func(r *Rego) {
	return func(r *Rego) {
		r.query = q
	}
}

// ParsedQuery returns an argument that sets the Rego query.
func ParsedQuery(q ast.Body) func(r *Rego) {
	return func(r *Rego) {
		r.parsedQuery = q
	}
}

// Package returns an argument that sets the Rego package on the query's
// context.
func Package(p string) func(r *Rego) {
	return func(r *Rego) {
		r.pkg = p
	}
}

// ParsedPackage returns an argument that sets the Rego package on the query's
// context.
func ParsedPackage(pkg *ast.Package) func(r *Rego) {
	return func(r *Rego) {
		r.parsedPackage = pkg
	}
}

// Imports returns an argument that adds a Rego import to the query's context.
func Imports(p []string) func(r *Rego) {
	return func(r *Rego) {
		r.imports = append(r.imports, p...)
	}
}

// ParsedImports returns an argument that adds Rego imports to the query's
// context.
func ParsedImports(imp []*ast.Import) func(r *Rego) {
	return func(r *Rego) {
		r.parsedImports = append(r.parsedImports, imp...)
	}
}

// Input returns an argument that sets the Rego input document. Input should be
// a native Go value representing the input document.
func Input(x any) func(r *Rego) {
	return func(r *Rego) {
		r.rawInput = &x
	}
}

// ParsedInput returns an argument that sets the Rego input document.
func ParsedInput(x ast.Value) func(r *Rego) {
	return func(r *Rego) {
		r.parsedInput = x
	}
}

// Unknowns returns an argument that sets the values to treat as unknown during
// partial evaluation.
func Unknowns(unknowns []string) func(r *Rego) {
	return func(r *Rego) {
		r.unknowns = unknowns
	}
}

// ParsedUnknowns returns an argument that sets the values to treat as unknown
// during partial evaluation.
func ParsedUnknowns(unknowns []*ast.Term) func(r *Rego) {
	return func(r *Rego) {
		r.parsedUnknowns = unknowns
	}
}

// DisableInlining adds a set of paths to exclude from partial evaluation inlining.
func DisableInlining(paths []string) func(r *Rego) {
	return func(r *Rego) {
		r.disableInlining = paths
	}
}

// NondeterministicBuiltins causes non-deterministic builtins to be evalued during
// partial evaluation. This is needed to pull in external data, or validate a JWT,
// during PE, so that the result informs what queries are returned.
func NondeterministicBuiltins(yes bool) func(r *Rego) {
	return func(r *Rego) {
		r.nondeterministicBuiltins = yes
	}
}

// ShallowInlining prevents rules that depend on unknown values from being inlined.
// Rules that only depend on known values are inlined.
func ShallowInlining(yes bool) func(r *Rego) {
	return func(r *Rego) {
		r.shallowInlining = yes
	}
}

// SkipPartialNamespace disables namespacing of partial evalution results for support
// rules generated from policy. Synthetic support rules are still namespaced.
func SkipPartialNamespace(yes bool) func(r *Rego) {
	return func(r *Rego) {
		r.skipPartialNamespace = yes
	}
}

// PartialNamespace returns an argument that sets the namespace to use for
// partial evaluation results. The namespace must be a valid package path
// component.
func PartialNamespace(ns string) func(r *Rego) {
	return func(r *Rego) {
		r.partialNamespace = ns
	}
}

// Module returns an argument that adds a Rego module.
func Module(filename, input string) func(r *Rego) {
	return func(r *Rego) {
		r.modules = append(r.modules, rawModule{
			filename: filename,
			module:   input,
		})
	}
}

// ParsedModule returns an argument that adds a parsed Rego module. If a string
// module with the same filename name is added, it will override the parsed
// module.
func ParsedModule(module *ast.Module) func(*Rego) {
	return func(r *Rego) {
		var filename string
		if module.Package.Location != nil {
			filename = module.Package.Location.File
		} else {
			filename = fmt.Sprintf("module_%p.rego", module)
		}
		r.parsedModules[filename] = module
	}
}

// Load returns an argument that adds a filesystem path to load data
// and Rego modules from. Any file with a *.rego, *.yaml, or *.json
// extension will be loaded. The path can be either a directory or file,
// directories are loaded recursively. The optional ignore string patterns
// can be used to filter which files are used.
// The Load option can only be used once.
// Note: Loading files will require a write transaction on the store.
func Load(paths []string, filter loader.Filter) func(r *Rego) {
	return func(r *Rego) {
		r.loadPaths = loadPaths{paths, filter}
	}
}

// LoadBundle returns an argument that adds a filesystem path to load
// a bundle from. The path can be a compressed bundle file or a directory
// to be loaded as a bundle.
// Note: Loading bundles will require a write transaction on the store.
func LoadBundle(path string) func(r *Rego) {
	return func(r *Rego) {
		r.bundlePaths = append(r.bundlePaths, path)
	}
}

// ParsedBundle returns an argument that adds a bundle to be loaded.
func ParsedBundle(name string, b *bundle.Bundle) func(r *Rego) {
	return func(r *Rego) {
		r.bundles[name] = b
	}
}

// Compiler returns an argument that sets the Rego compiler.
func Compiler(c *ast.Compiler) func(r *Rego) {
	return func(r *Rego) {
		r.compiler = c
	}
}

// Store returns an argument that sets the policy engine's data storage layer.
//
// If using the Load, LoadBundle, or ParsedBundle options then a transaction
// must also be provided via the Transaction() option. After loading files
// or bundles the transaction should be aborted or committed.
func Store(s storage.Store) func(r *Rego) {
	return func(r *Rego) {
		r.store = s
	}
}

// StoreReadAST returns an argument that sets whether the store should eagerly convert data to AST values.
//
// Only applicable when no store has been set on the Rego object through the Store option.
func StoreReadAST(enabled bool) func(r *Rego) {
	return func(r *Rego) {
		r.ownStoreReadAst = enabled
	}
}

// Transaction returns an argument that sets the transaction to use for storage
// layer operations.
//
// Requires the store associated with the transaction to be provided via the
// Store() option. If using Load(), LoadBundle(), or ParsedBundle() options
// the transaction will likely require write params.
func Transaction(txn storage.Transaction) func(r *Rego) {
	return func(r *Rego) {
		r.txn = txn
	}
}

// Metrics returns an argument that sets the metrics collection.
func Metrics(m metrics.Metrics) func(r *Rego) {
	return func(r *Rego) {
		r.metrics = m
	}
}

// Instrument returns an argument that enables instrumentation for diagnosing
// performance issues.
func Instrument(yes bool) func(r *Rego) {
	return func(r *Rego) {
		r.instrument = yes
	}
}

// Trace returns an argument that enables tracing on r.
func Trace(yes bool) func(r *Rego) {
	return func(r *Rego) {
		r.trace = yes
	}
}

// Tracer returns an argument that adds a query tracer to r.
// Deprecated: Use QueryTracer instead.
func Tracer(t topdown.Tracer) func(r *Rego) {
	return func(r *Rego) {
		if t != nil {
			r.queryTracers = append(r.queryTracers, topdown.WrapLegacyTracer(t))
		}
	}
}

// QueryTracer returns an argument that adds a query tracer to r.
func QueryTracer(t topdown.QueryTracer) func(r *Rego) {
	return func(r *Rego) {
		if t != nil {
			r.queryTracers = append(r.queryTracers, t)
		}
	}
}

// Runtime returns an argument that sets the runtime data to provide to the
// evaluation engine.
func Runtime(term *ast.Term) func(r *Rego) {
	return func(r *Rego) {
		r.runtime = term
	}
}

// Time sets the wall clock time to use during policy evaluation. Prepared queries
// do not inherit this parameter. Use EvalTime to set the wall clock time when
// executing a prepared query.
func Time(x time.Time) func(r *Rego) {
	return func(r *Rego) {
		r.time = x
	}
}

// Seed sets a reader that will seed randomization required by built-in functions.
// If a seed is not provided crypto/rand.Reader is used.
func Seed(r io.Reader) func(*Rego) {
	return func(e *Rego) {
		e.seed = r
	}
}

// PrintTrace is a helper function to write a human-readable version of the
// trace to the writer w.
func PrintTrace(w io.Writer, r *Rego) {
	if r == nil || r.tracebuf == nil {
		return
	}
	topdown.PrettyTrace(w, *r.tracebuf)
}

// PrintTraceWithLocation is a helper function to write a human-readable version of the
// trace to the writer w.
func PrintTraceWithLocation(w io.Writer, r *Rego) {
	if r == nil || r.tracebuf == nil {
		return
	}
	topdown.PrettyTraceWithLocation(w, *r.tracebuf)
}

// UnsafeBuiltins sets the built-in functions to treat as unsafe and not allow.
// This option is ignored for module compilation if the caller supplies the
// compiler. This option is always honored for query compilation. Provide an
// empty (non-nil) map to disable checks on queries.
func UnsafeBuiltins(unsafeBuiltins map[string]struct{}) func(r *Rego) {
	return func(r *Rego) {
		r.unsafeBuiltins = unsafeBuiltins
	}
}

// SkipBundleVerification skips verification of a signed bundle.
func SkipBundleVerification(yes bool) func(r *Rego) {
	return func(r *Rego) {
		r.skipBundleVerification = yes
	}
}

// BundleActivatorPlugin sets the name of the activator plugin used to load bundles into the store.
func BundleActivatorPlugin(name string) func(r *Rego) {
	return func(r *Rego) {
		r.bundleActivationPlugin = name
	}
}

// BundleLazyLoadingMode sets the bundle loading mode. If true, bundles will be
// read in lazy mode. In this mode, data files in the bundle will not be
// deserialized and the check to validate that the bundle data does not contain
// paths outside the bundle's roots will not be performed while reading the bundle.
func BundleLazyLoadingMode(yes bool) func(r *Rego) {
	return func(r *Rego) {
		r.enableBundleLazyLoadingMode = yes
	}
}

// InterQueryBuiltinCache sets the inter-query cache that built-in functions can utilize
// during evaluation.
func InterQueryBuiltinCache(c cache.InterQueryCache) func(r *Rego) {
	return func(r *Rego) {
		r.interQueryBuiltinCache = c
	}
}

// InterQueryBuiltinValueCache sets the inter-query value cache that built-in functions can utilize
// during evaluation.
func InterQueryBuiltinValueCache(c cache.InterQueryValueCache) func(r *Rego) {
	return func(r *Rego) {
		r.interQueryBuiltinValueCache = c
	}
}

// NDBuiltinCache sets the non-deterministic builtins cache.
func NDBuiltinCache(c builtins.NDBCache) func(r *Rego) {
	return func(r *Rego) {
		r.ndBuiltinCache = c
	}
}

// StrictBuiltinErrors tells the evaluator to treat all built-in function errors as fatal errors.
func StrictBuiltinErrors(yes bool) func(r *Rego) {
	return func(r *Rego) {
		r.strictBuiltinErrors = yes
	}
}

// BuiltinErrorList supplies an error slice to store built-in function errors.
func BuiltinErrorList(list *[]topdown.Error) func(r *Rego) {
	return func(r *Rego) {
		r.builtinErrorList = list
	}
}

// Resolver sets a Resolver for a specified ref path.
func Resolver(ref ast.Ref, r resolver.Resolver) func(r *Rego) {
	return func(rego *Rego) {
		rego.resolvers = append(rego.resolvers, refResolver{ref, r})
	}
}

// Schemas sets the schemaSet
func Schemas(x *ast.SchemaSet) func(r *Rego) {
	return func(r *Rego) {
		r.schemaSet = x
	}
}

// Capabilities configures the underlying compiler's capabilities.
// This option is ignored for module compilation if the caller supplies the
// compiler.
func Capabilities(c *ast.Capabilities) func(r *Rego) {
	return func(r *Rego) {
		r.capabilities = c
	}
}

// Target sets the runtime to exercise.
func Target(t string) func(r *Rego) {
	return func(r *Rego) {
		r.target = t
	}
}

// GenerateJSON sets the AST to JSON converter for the results.
func GenerateJSON(f func(*ast.Term, *EvalContext) (any, error)) func(r *Rego) {
	return func(r *Rego) {
		r.generateJSON = f
	}
}

// PrintHook sets the object to use for handling print statement outputs.
func PrintHook(h print.Hook) func(r *Rego) {
	return func(r *Rego) {
		r.printHook = h
	}
}

// DistributedTracingOpts sets the options to be used by distributed tracing.
func DistributedTracingOpts(tr tracing.Options) func(r *Rego) {
	return func(r *Rego) {
		r.distributedTracingOpts = tr
	}
}

// EnablePrintStatements enables print() calls. If this option is not provided,
// print() calls will be erased from the policy. This option only applies to
// queries and policies that passed as raw strings, i.e., this function will not
// have any affect if the caller supplies the ast.Compiler instance.
func EnablePrintStatements(yes bool) func(r *Rego) {
	return func(r *Rego) {
		r.enablePrintStatements = yes
	}
}

// Strict enables or disables strict-mode in the compiler
func Strict(yes bool) func(r *Rego) {
	return func(r *Rego) {
		r.strict = yes
	}
}

func SetRegoVersion(version ast.RegoVersion) func(r *Rego) {
	return func(r *Rego) {
		r.regoVersion = version
	}
}

// CompilerHook sets a hook function that will be called after the compiler is initialized.
// This is only called if the compiler has not been provided already.
func CompilerHook(hook func(*ast.Compiler)) func(r *Rego) {
	return func(r *Rego) {
		r.compilerHook = hook
	}
}

// EvalMode lets you override the evaluation mode.
func EvalMode(mode ast.CompilerEvalMode) func(r *Rego) {
	return func(r *Rego) {
		r.evalMode = &mode
	}
}

// New returns a new Rego object.
func New(options ...func(r *Rego)) *Rego {

	r := &Rego{
		parsedModules:   map[string]*ast.Module{},
		capture:         map[*ast.Expr]ast.Var{},
		compiledQueries: map[queryType]compiledQuery{},
		builtinDecls:    map[string]*ast.Builtin{},
		builtinFuncs:    map[string]*topdown.Builtin{},
		bundles:         map[string]*bundle.Bundle{},
	}

	for _, option := range options {
		option(r)
	}

	callHook := r.compiler == nil // call hook only if we created the compiler here

	if r.compiler == nil {
		r.compiler = ast.NewCompiler().
			WithUnsafeBuiltins(r.unsafeBuiltins).
			WithBuiltins(r.builtinDecls).
			WithDebug(r.dump).
			WithSchemas(r.schemaSet).
			WithCapabilities(r.capabilities).
			WithEnablePrintStatements(r.enablePrintStatements).
			WithStrict(r.strict).
			WithUseTypeCheckAnnotations(true)

		// topdown could be target "" or "rego", but both could be overridden by
		// a target plugin (checked below)
		if r.target == targetWasm {
			r.compiler = r.compiler.WithEvalMode(ast.EvalModeIR)
		}

		if r.regoVersion != ast.RegoUndefined {
			r.compiler = r.compiler.WithDefaultRegoVersion(r.regoVersion)
		}
	}

	if r.store == nil {
		if bundle.HasExtension() {
			r.store = bundle.BundleExtStore()
		} else {
			r.store = inmem.NewWithOpts(inmem.OptReturnASTValuesOnRead(r.ownStoreReadAst))
		}
		r.ownStore = true
	} else {
		r.ownStore = false
	}

	if r.metrics == nil {
		r.metrics = metrics.New()
	}

	if r.instrument {
		r.instrumentation = topdown.NewInstrumentation(r.metrics)
		r.compiler.WithMetrics(r.metrics)
	}

	if r.trace {
		r.tracebuf = topdown.NewBufferTracer()
		r.queryTracers = append(r.queryTracers, r.tracebuf)
	}

	if r.partialNamespace == "" {
		r.partialNamespace = defaultPartialNamespace
	}

	if r.generateJSON == nil {
		r.generateJSON = generateJSON
	}

	if r.pluginMgr != nil {
		for _, name := range r.pluginMgr.Plugins() {
			p := r.pluginMgr.Plugin(name)
			if p0, ok := p.(TargetPlugin); ok {
				r.plugins = append(r.plugins, p0)
			}
		}
	}

	if t := r.targetPlugin(r.target); t != nil {
		r.compiler = r.compiler.WithEvalMode(ast.EvalModeIR)
	}

	if r.evalMode != nil {
		r.compiler = r.compiler.WithEvalMode(*r.evalMode)
	}

	if r.compilerHook != nil && callHook {
		r.compilerHook(r.compiler)
	}

	return r
}

// Eval evaluates this Rego object and returns a ResultSet.
func (r *Rego) Eval(ctx context.Context) (ResultSet, error) {
	var err error
	var txnClose transactionCloser
	r.txn, txnClose, err = r.getTxn(ctx)
	if err != nil {
		return nil, err
	}

	pq, err := r.PrepareForEval(ctx)
	if err != nil {
		_ = txnClose(ctx, err) // Ignore error
		return nil, err
	}

	evalArgs := []EvalOption{
		EvalTransaction(r.txn),
		EvalMetrics(r.metrics),
		EvalInstrument(r.instrument),
		EvalTime(r.time),
		EvalInterQueryBuiltinCache(r.interQueryBuiltinCache),
		EvalInterQueryBuiltinValueCache(r.interQueryBuiltinValueCache),
		EvalSeed(r.seed),
	}

	if r.ndBuiltinCache != nil {
		evalArgs = append(evalArgs, EvalNDBuiltinCache(r.ndBuiltinCache))
	}

	for _, qt := range r.queryTracers {
		evalArgs = append(evalArgs, EvalQueryTracer(qt))
	}

	for i := range r.resolvers {
		evalArgs = append(evalArgs, EvalResolver(r.resolvers[i].ref, r.resolvers[i].r))
	}

	rs, err := pq.Eval(ctx, evalArgs...)
	txnErr := txnClose(ctx, err) // Always call closer
	if err == nil {
		err = txnErr
	}
	return rs, err
}

// PartialEval has been deprecated and renamed to PartialResult.
func (r *Rego) PartialEval(ctx context.Context) (PartialResult, error) {
	return r.PartialResult(ctx)
}

// PartialResult partially evaluates this Rego object and returns a PartialResult.
func (r *Rego) PartialResult(ctx context.Context) (PartialResult, error) {
	var err error
	var txnClose transactionCloser
	r.txn, txnClose, err = r.getTxn(ctx)
	if err != nil {
		return PartialResult{}, err
	}

	pq, err := r.PrepareForEval(ctx, WithPartialEval())
	txnErr := txnClose(ctx, err) // Always call closer
	if err != nil {
		return PartialResult{}, err
	}
	if txnErr != nil {
		return PartialResult{}, txnErr
	}

	pr := PartialResult{
		compiler:     pq.r.compiler,
		store:        pq.r.store,
		body:         pq.r.parsedQuery,
		builtinDecls: pq.r.builtinDecls,
		builtinFuncs: pq.r.builtinFuncs,
	}

	return pr, nil
}

// Partial runs partial evaluation on r and returns the result.
func (r *Rego) Partial(ctx context.Context) (*PartialQueries, error) {
	var err error
	var txnClose transactionCloser
	r.txn, txnClose, err = r.getTxn(ctx)
	if err != nil {
		return nil, err
	}

	pq, err := r.PrepareForPartial(ctx)
	if err != nil {
		_ = txnClose(ctx, err) // Ignore error
		return nil, err
	}

	evalArgs := []EvalOption{
		EvalTransaction(r.txn),
		EvalMetrics(r.metrics),
		EvalInstrument(r.instrument),
		EvalInterQueryBuiltinCache(r.interQueryBuiltinCache),
		EvalInterQueryBuiltinValueCache(r.interQueryBuiltinValueCache),
	}

	if r.ndBuiltinCache != nil {
		evalArgs = append(evalArgs, EvalNDBuiltinCache(r.ndBuiltinCache))
	}

	for _, t := range r.queryTracers {
		evalArgs = append(evalArgs, EvalQueryTracer(t))
	}

	for i := range r.resolvers {
		evalArgs = append(evalArgs, EvalResolver(r.resolvers[i].ref, r.resolvers[i].r))
	}

	pqs, err := pq.Partial(ctx, evalArgs...)
	txnErr := txnClose(ctx, err) // Always call closer
	if err == nil {
		err = txnErr
	}
	return pqs, err
}

// CompileOption defines a function to set options on Compile calls.
type CompileOption func(*CompileContext)

// CompileContext contains options for Compile calls.
type CompileContext struct {
	partial bool
}

// CompilePartial defines an option to control whether partial evaluation is run
// before the query is planned and compiled.
func CompilePartial(yes bool) CompileOption {
	return func(cfg *CompileContext) {
		cfg.partial = yes
	}
}

// Compile returns a compiled policy query.
func (r *Rego) Compile(ctx context.Context, opts ...CompileOption) (*CompileResult, error) {

	var cfg CompileContext

	for _, opt := range opts {
		opt(&cfg)
	}

	var queries []ast.Body
	modules := make([]*ast.Module, 0, len(r.compiler.Modules))

	if cfg.partial {

		pq, err := r.Partial(ctx)
		if err != nil {
			return nil, err
		}
		if r.dump != nil {
			if len(pq.Queries) != 0 {
				msg := fmt.Sprintf("QUERIES (%d total):", len(pq.Queries))
				fmt.Fprintln(r.dump, msg)
				fmt.Fprintln(r.dump, strings.Repeat("-", len(msg)))
				for i := range pq.Queries {
					fmt.Println(pq.Queries[i])
				}
				fmt.Fprintln(r.dump)
			}
			if len(pq.Support) != 0 {
				msg := fmt.Sprintf("SUPPORT (%d total):", len(pq.Support))
				fmt.Fprintln(r.dump, msg)
				fmt.Fprintln(r.dump, strings.Repeat("-", len(msg)))
				for i := range pq.Support {
					fmt.Println(pq.Support[i])
				}
				fmt.Fprintln(r.dump)
			}
		}

		queries = pq.Queries
		modules = pq.Support

		for _, module := range r.compiler.Modules {
			modules = append(modules, module)
		}
	} else {
		var err error
		// If creating a new transaction it should be closed before calling the
		// planner to avoid holding open the transaction longer than needed.
		//
		// TODO(tsandall): in future, planner could make use of store, in which
		// case this will need to change.
		var txnClose transactionCloser
		r.txn, txnClose, err = r.getTxn(ctx)
		if err != nil {
			return nil, err
		}

		err = r.prepare(ctx, compileQueryType, nil)
		txnErr := txnClose(ctx, err) // Always call closer
		if err != nil {
			return nil, err
		}
		if txnErr != nil {
			return nil, err
		}

		for _, module := range r.compiler.Modules {
			modules = append(modules, module)
		}

		queries = []ast.Body{r.compiledQueries[compileQueryType].query}
	}

	if tgt := r.targetPlugin(r.target); tgt != nil {
		return nil, errors.New("unsupported for rego target plugins")
	}

	return r.compileWasm(modules, queries, compileQueryType) // TODO(sr) control flow is funky here
}

func (r *Rego) compileWasm(_ []*ast.Module, queries []ast.Body, qType queryType) (*CompileResult, error) {
	policy, err := r.planQuery(queries, qType)
	if err != nil {
		return nil, err
	}

	m, err := wasm.New().WithPolicy(policy).Compile()
	if err != nil {
		return nil, err
	}

	var out bytes.Buffer
	if err := encoding.WriteModule(&out, m); err != nil {
		return nil, err
	}

	return &CompileResult{
		Bytes: out.Bytes(),
	}, nil
}

// PrepareOption defines a function to set an option to control
// the behavior of the Prepare call.
type PrepareOption func(*PrepareConfig)

// PrepareConfig holds settings to control the behavior of the
// Prepare call.
type PrepareConfig struct {
	doPartialEval   bool
	disableInlining *[]string
	builtinFuncs    map[string]*topdown.Builtin
}

// WithPartialEval configures an option for PrepareForEval
// which will have it perform partial evaluation while preparing
// the query (similar to rego.Rego#PartialResult)
func WithPartialEval() PrepareOption {
	return func(p *PrepareConfig) {
		p.doPartialEval = true
	}
}

// WithNoInline adds a set of paths to exclude from partial evaluation inlining.
func WithNoInline(paths []string) PrepareOption {
	return func(p *PrepareConfig) {
		p.disableInlining = &paths
	}
}

// WithBuiltinFuncs carries the rego.Function{1,2,3} per-query function definitions
// to the target plugins.
func WithBuiltinFuncs(bis map[string]*topdown.Builtin) PrepareOption {
	return func(p *PrepareConfig) {
		if p.builtinFuncs == nil {
			p.builtinFuncs = maps.Clone(bis)
		} else {
			maps.Copy(p.builtinFuncs, bis)
		}
	}
}

// BuiltinFuncs allows retrieving the builtin funcs set via PrepareOption
// WithBuiltinFuncs.
func (p *PrepareConfig) BuiltinFuncs() map[string]*topdown.Builtin {
	return p.builtinFuncs
}

// PrepareForEval will parse inputs, modules, and query arguments in preparation
// of evaluating them.
func (r *Rego) PrepareForEval(ctx context.Context, opts ...PrepareOption) (PreparedEvalQuery, error) {
	if !r.hasQuery() {
		return PreparedEvalQuery{}, errors.New("cannot evaluate empty query")
	}

	pCfg := &PrepareConfig{}
	for _, o := range opts {
		o(pCfg)
	}

	var err error
	var txnClose transactionCloser
	r.txn, txnClose, err = r.getTxn(ctx)
	if err != nil {
		return PreparedEvalQuery{}, err
	}

	// If the caller wanted to do partial evaluation as part of preparation
	// do it now and use the new Rego object.
	if pCfg.doPartialEval {

		pr, err := r.partialResult(ctx, pCfg)
		if err != nil {
			_ = txnClose(ctx, err) // Ignore error
			return PreparedEvalQuery{}, err
		}

		// Prepare the new query using the result of partial evaluation
		pq, err := pr.Rego(Transaction(r.txn)).PrepareForEval(ctx)
		txnErr := txnClose(ctx, err)
		if err != nil {
			return pq, err
		}
		return pq, txnErr
	}

	err = r.prepare(ctx, evalQueryType, []extraStage{
		{
			after: "ResolveRefs",
			stage: ast.QueryCompilerStageDefinition{
				Name:       "RewriteToCaptureValue",
				MetricName: "query_compile_stage_rewrite_to_capture_value",
				Stage:      r.rewriteQueryToCaptureValue,
			},
		},
	})
	if err != nil {
		_ = txnClose(ctx, err) // Ignore error
		return PreparedEvalQuery{}, err
	}

	switch r.target {
	case targetWasm: // TODO(sr): make wasm a target plugin, too

		if r.hasWasmModule() {
			_ = txnClose(ctx, err) // Ignore error
			return PreparedEvalQuery{}, errors.New("wasm target not supported")
		}

		var modules []*ast.Module
		for _, module := range r.compiler.Modules {
			modules = append(modules, module)
		}

		queries := []ast.Body{r.compiledQueries[evalQueryType].query}

		e, err := opa.LookupEngine(targetWasm)
		if err != nil {
			return PreparedEvalQuery{}, err
		}

		// nolint: staticcheck // SA4006 false positive
		cr, err := r.compileWasm(modules, queries, evalQueryType)
		if err != nil {
			_ = txnClose(ctx, err) // Ignore error
			return PreparedEvalQuery{}, err
		}

		// nolint: staticcheck // SA4006 false positive
		data, err := r.store.Read(ctx, r.txn, storage.Path{})
		if err != nil {
			_ = txnClose(ctx, err) // Ignore error
			return PreparedEvalQuery{}, err
		}

		o, err := e.New().WithPolicyBytes(cr.Bytes).WithDataJSON(data).Init()
		if err != nil {
			_ = txnClose(ctx, err) // Ignore error
			return PreparedEvalQuery{}, err
		}
		r.opa = o

	case targetRego: // do nothing, don't lookup default plugin
	default: // either a specific plugin target, or one that is default
		if tgt := r.targetPlugin(r.target); tgt != nil {
			queries := []ast.Body{r.compiledQueries[evalQueryType].query}
			pol, err := r.planQuery(queries, evalQueryType)
			if err != nil {
				return PreparedEvalQuery{}, err
			}
			// always add the builtins provided via rego.FunctionN options
			opts = append(opts, WithBuiltinFuncs(r.builtinFuncs))
			r.targetPrepState, err = tgt.PrepareForEval(ctx, pol, opts...)
			if err != nil {
				return PreparedEvalQuery{}, err
			}
		}
	}

	txnErr := txnClose(ctx, err) // Always call closer
	if txnErr != nil {
		return PreparedEvalQuery{}, txnErr
	}

	return PreparedEvalQuery{preparedQuery{r, pCfg}}, err
}

// PrepareForPartial will parse inputs, modules, and query arguments in preparation
// of partially evaluating them.
func (r *Rego) PrepareForPartial(ctx context.Context, opts ...PrepareOption) (PreparedPartialQuery, error) {
	if !r.hasQuery() {
		return PreparedPartialQuery{}, errors.New("cannot evaluate empty query")
	}

	pCfg := &PrepareConfig{}
	for _, o := range opts {
		o(pCfg)
	}

	var err error
	var txnClose transactionCloser
	r.txn, txnClose, err = r.getTxn(ctx)
	if err != nil {
		return PreparedPartialQuery{}, err
	}

	err = r.prepare(ctx, partialQueryType, []extraStage{
		{
			after: "CheckSafety",
			stage: ast.QueryCompilerStageDefinition{
				Name:       "RewriteEquals",
				MetricName: "query_compile_stage_rewrite_equals",
				Stage:      r.rewriteEqualsForPartialQueryCompile,
			},
		},
	})
	txnErr := txnClose(ctx, err) // Always call closer
	if err != nil {
		return PreparedPartialQuery{}, err
	}
	if txnErr != nil {
		return PreparedPartialQuery{}, txnErr
	}

	return PreparedPartialQuery{preparedQuery{r, pCfg}}, err
}

func (r *Rego) prepare(ctx context.Context, qType queryType, extras []extraStage) error {
	var err error

	r.parsedInput, err = r.parseInput()
	if err != nil {
		return err
	}

	err = r.loadFiles(ctx, r.txn, r.metrics)
	if err != nil {
		return err
	}

	err = r.loadBundles(ctx, r.txn, r.metrics)
	if err != nil {
		return err
	}

	err = r.parseModules(ctx, r.txn, r.metrics)
	if err != nil {
		return err
	}

	// Compile the modules *before* the query, else functions
	// defined in the module won't be found...
	err = r.compileModules(ctx, r.txn, r.metrics)
	if err != nil {
		return err
	}

	imports, err := r.prepareImports()
	if err != nil {
		return err
	}

	queryImports := []*ast.Import{}
	for _, imp := range imports {
		path := imp.Path.Value.(ast.Ref)
		if path.HasPrefix([]*ast.Term{ast.FutureRootDocument}) || path.HasPrefix([]*ast.Term{ast.RegoRootDocument}) {
			queryImports = append(queryImports, imp)
		}
	}

	r.parsedQuery, err = r.parseQuery(queryImports, r.metrics)
	if err != nil {
		return err
	}

	err = r.compileAndCacheQuery(qType, r.parsedQuery, imports, r.metrics, extras)
	if err != nil {
		return err
	}

	return nil
}

func (r *Rego) parseModules(ctx context.Context, txn storage.Transaction, m metrics.Metrics) error {
	if len(r.modules) == 0 {
		return nil
	}

	ids, err := r.store.ListPolicies(ctx, txn)
	if err != nil {
		return err
	}

	m.Timer(metrics.RegoModuleParse).Start()
	defer m.Timer(metrics.RegoModuleParse).Stop()
	var errs Errors

	popts := ast.ParserOptions{
		RegoVersion:  r.regoVersion,
		Capabilities: r.capabilities,
	}

	// Parse any modules that are saved to the store, but only if
	// another compile step is going to occur (ie. we have parsed modules
	// that need to be compiled).
	for _, id := range ids {
		// if it is already on the compiler we're using
		// then don't bother to re-parse it from source
		if _, haveMod := r.compiler.Modules[id]; haveMod {
			continue
		}

		bs, err := r.store.GetPolicy(ctx, txn, id)
		if err != nil {
			return err
		}

		parsed, err := ast.ParseModuleWithOpts(id, string(bs), popts)
		if err != nil {
			errs = append(errs, err)
		}

		r.parsedModules[id] = parsed
	}

	// Parse any passed in as arguments to the Rego object
	for _, module := range r.modules {
		p, err := module.ParseWithOpts(popts)
		if err != nil {
			switch errorWithType := err.(type) {
			case ast.Errors:
				for _, e := range errorWithType {
					errs = append(errs, e)
				}
			default:
				errs = append(errs, errorWithType)
			}
		}
		r.parsedModules[module.filename] = p
	}

	if len(errs) > 0 {
		return errs
	}

	return nil
}

func (r *Rego) loadFiles(ctx context.Context, txn storage.Transaction, m metrics.Metrics) error {
	if len(r.loadPaths.paths) == 0 {
		return nil
	}

	m.Timer(metrics.RegoLoadFiles).Start()
	defer m.Timer(metrics.RegoLoadFiles).Stop()

	result, err := loader.NewFileLoader().
		WithMetrics(m).
		WithProcessAnnotation(true).
		WithBundleLazyLoadingMode(bundle.HasExtension()).
		WithRegoVersion(r.regoVersion).
		WithCapabilities(r.capabilities).
		Filtered(r.loadPaths.paths, r.loadPaths.filter)
	if err != nil {
		return err
	}
	for name, mod := range result.Modules {
		r.parsedModules[name] = mod.Parsed
	}

	if len(result.Documents) > 0 {
		err = r.store.Write(ctx, txn, storage.AddOp, storage.Path{}, result.Documents)
		if err != nil {
			return err
		}
	}
	return nil
}

func (r *Rego) loadBundles(_ context.Context, _ storage.Transaction, m metrics.Metrics) error {
	if len(r.bundlePaths) == 0 {
		return nil
	}

	m.Timer(metrics.RegoLoadBundles).Start()
	defer m.Timer(metrics.RegoLoadBundles).Stop()

	for _, path := range r.bundlePaths {
		bndl, err := loader.NewFileLoader().
			WithMetrics(m).
			WithProcessAnnotation(true).
			WithBundleLazyLoadingMode(bundle.HasExtension()).
			WithSkipBundleVerification(r.skipBundleVerification).
			WithRegoVersion(r.regoVersion).
			WithCapabilities(r.capabilities).
			AsBundle(path)
		if err != nil {
			return fmt.Errorf("loading error: %s", err)
		}
		r.bundles[path] = bndl
	}
	return nil
}

func (r *Rego) parseInput() (ast.Value, error) {
	if r.parsedInput != nil {
		return r.parsedInput, nil
	}
	return r.parseRawInput(r.rawInput, r.metrics)
}

func (*Rego) parseRawInput(rawInput *any, m metrics.Metrics) (ast.Value, error) {
	var input ast.Value

	if rawInput == nil {
		return input, nil
	}

	m.Timer(metrics.RegoInputParse).Start()
	defer m.Timer(metrics.RegoInputParse).Stop()

	rawPtr := util.Reference(rawInput)

	// roundtrip through json: this turns slices (e.g. []string, []bool) into
	// []any, the only array type ast.InterfaceToValue can work with
	if err := util.RoundTrip(rawPtr); err != nil {
		return nil, err
	}

	return ast.InterfaceToValue(*rawPtr)
}

func (r *Rego) parseQuery(queryImports []*ast.Import, m metrics.Metrics) (ast.Body, error) {
	if r.parsedQuery != nil {
		return r.parsedQuery, nil
	}

	m.Timer(metrics.RegoQueryParse).Start()
	defer m.Timer(metrics.RegoQueryParse).Stop()

	popts, err := future.ParserOptionsFromFutureImports(queryImports)
	if err != nil {
		return nil, err
	}
	popts.RegoVersion = r.regoVersion
	popts, err = parserOptionsFromRegoVersionImport(queryImports, popts)
	if err != nil {
		return nil, err
	}
	popts.SkipRules = true
	popts.Capabilities = r.capabilities

	return ast.ParseBodyWithOpts(r.query, popts)
}

func parserOptionsFromRegoVersionImport(imports []*ast.Import, popts ast.ParserOptions) (ast.ParserOptions, error) {
	for _, imp := range imports {
		path := imp.Path.Value.(ast.Ref)
		if ast.Compare(path, ast.RegoV1CompatibleRef) == 0 {
			popts.RegoVersion = ast.RegoV1
			return popts, nil
		}
	}
	return popts, nil
}

func (r *Rego) compileModules(ctx context.Context, txn storage.Transaction, m metrics.Metrics) error {

	// Only compile again if there are new modules.
	if len(r.bundles) > 0 || len(r.parsedModules) > 0 {

		// The bundle.Activate call will activate any bundles passed in
		// (ie compile + handle data store changes), and include any of
		// the additional modules passed in. If no bundles are provided
		// it will only compile the passed in modules.
		// Use this as the single-point of compiling everything only a
		// single time.
		opts := &bundle.ActivateOpts{
			Ctx:           ctx,
			Store:         r.store,
			Txn:           txn,
			Compiler:      r.compilerForTxn(ctx, r.store, txn),
			Metrics:       m,
			Bundles:       r.bundles,
			ExtraModules:  r.parsedModules,
			ParserOptions: ast.ParserOptions{RegoVersion: r.regoVersion},
		}
		err := bundle.Activate(opts)
		if err != nil {
			return err
		}
	}

	// Ensure all configured resolvers from the store are loaded. Skip if any were explicitly provided.
	if len(r.resolvers) == 0 {
		resolvers, err := bundleUtils.LoadWasmResolversFromStore(ctx, r.store, txn, r.bundles)
		if err != nil {
			return err
		}

		for _, rslvr := range resolvers {
			for _, ep := range rslvr.Entrypoints() {
				r.resolvers = append(r.resolvers, refResolver{ep, rslvr})
			}
		}
	}
	return nil
}

func (r *Rego) compileAndCacheQuery(qType queryType, query ast.Body, imports []*ast.Import, m metrics.Metrics, extras []extraStage) error {
	m.Timer(metrics.RegoQueryCompile).Start()
	defer m.Timer(metrics.RegoQueryCompile).Stop()

	cachedQuery, ok := r.compiledQueries[qType]
	if ok && cachedQuery.query != nil && cachedQuery.compiler != nil {
		return nil
	}

	qc, compiled, err := r.compileQuery(query, imports, m, extras)
	if err != nil {
		return err
	}

	// cache the query for future use
	r.compiledQueries[qType] = compiledQuery{
		query:    compiled,
		compiler: qc,
	}
	return nil
}

func (r *Rego) prepareImports() ([]*ast.Import, error) {
	imports := r.parsedImports

	if len(r.imports) > 0 {
		s := make([]string, len(r.imports))
		for i := range r.imports {
			s[i] = fmt.Sprintf("import %v", r.imports[i])
		}
		parsed, err := ast.ParseImports(strings.Join(s, "\n"))
		if err != nil {
			return nil, err
		}
		imports = append(imports, parsed...)
	}
	return imports, nil
}

func (r *Rego) compileQuery(query ast.Body, imports []*ast.Import, _ metrics.Metrics, extras []extraStage) (ast.QueryCompiler, ast.Body, error) {
	var pkg *ast.Package

	if r.pkg != "" {
		var err error
		pkg, err = ast.ParsePackage(fmt.Sprintf("package %v", r.pkg))
		if err != nil {
			return nil, nil, err
		}
	} else {
		pkg = r.parsedPackage
	}

	qctx := ast.NewQueryContext().
		WithPackage(pkg).
		WithImports(imports)

	qc := r.compiler.QueryCompiler().
		WithContext(qctx).
		WithUnsafeBuiltins(r.unsafeBuiltins).
		WithEnablePrintStatements(r.enablePrintStatements).
		WithStrict(false)

	for _, extra := range extras {
		qc = qc.WithStageAfter(extra.after, extra.stage)
	}

	compiled, err := qc.Compile(query)

	return qc, compiled, err

}

func (r *Rego) eval(ctx context.Context, ectx *EvalContext) (ResultSet, error) {
	switch {
	case r.targetPrepState != nil: // target plugin flow
		var val ast.Value
		if r.runtime != nil {
			val = r.runtime.Value
		}
		s, err := r.targetPrepState.Eval(ctx, ectx, val)
		if err != nil {
			return nil, err
		}
		return r.valueToQueryResult(s, ectx)
	case r.target == targetWasm:
		return r.evalWasm(ctx, ectx)
	case r.target == targetRego: // continue
	}

	q := topdown.NewQuery(ectx.compiledQuery.query).
		WithQueryCompiler(ectx.compiledQuery.compiler).
		WithCompiler(r.compiler).
		WithStore(r.store).
		WithTransaction(ectx.txn).
		WithBuiltins(r.builtinFuncs).
		WithMetrics(ectx.metrics).
		WithInstrumentation(ectx.instrumentation).
		WithRuntime(r.runtime).
		WithIndexing(ectx.indexing).
		WithEarlyExit(ectx.earlyExit).
		WithInterQueryBuiltinCache(ectx.interQueryBuiltinCache).
		WithInterQueryBuiltinValueCache(ectx.interQueryBuiltinValueCache).
		WithStrictBuiltinErrors(r.strictBuiltinErrors).
		WithBuiltinErrorList(r.builtinErrorList).
		WithSeed(ectx.seed).
		WithPrintHook(ectx.printHook).
		WithDistributedTracingOpts(r.distributedTracingOpts).
		WithVirtualCache(ectx.virtualCache).
		WithBaseCache(ectx.baseCache)

	if !ectx.time.IsZero() {
		q = q.WithTime(ectx.time)
	}

	if ectx.ndBuiltinCache != nil {
		q = q.WithNDBuiltinCache(ectx.ndBuiltinCache)
	}

	for i := range ectx.queryTracers {
		q = q.WithQueryTracer(ectx.queryTracers[i])
	}

	if ectx.parsedInput != nil {
		q = q.WithInput(ast.NewTerm(ectx.parsedInput))
	}

	if ectx.httpRoundTripper != nil {
		q = q.WithHTTPRoundTripper(ectx.httpRoundTripper)
	}

	for i := range ectx.resolvers {
		q = q.WithResolver(ectx.resolvers[i].ref, ectx.resolvers[i].r)
	}

	// Cancel query if context is cancelled or deadline is reached.
	if ectx.externalCancel == nil {
		// Create a one-off goroutine to handle cancellation for this query.
		c := topdown.NewCancel()
		q = q.WithCancel(c)
		exit := make(chan struct{})
		defer close(exit)
		go waitForDone(ctx, exit, func() {
			c.Cancel()
		})
	} else {
		// Query cancellation is being handled elsewhere.
		q = q.WithCancel(ectx.externalCancel)
	}

	var rs ResultSet
	err := q.Iter(ctx, func(qr topdown.QueryResult) error {
		result, err := r.generateResult(qr, ectx)
		if err != nil {
			return err
		}
		rs = append(rs, result)
		return nil
	})

	if err != nil {
		return nil, err
	}

	if len(rs) == 0 {
		return nil, nil
	}

	return rs, nil
}

func (r *Rego) evalWasm(ctx context.Context, ectx *EvalContext) (ResultSet, error) {
	input := ectx.rawInput
	if ectx.parsedInput != nil {
		i := any(ectx.parsedInput)
		input = &i
	}
	result, err := r.opa.Eval(ctx, opa.EvalOpts{
		Metrics:                r.metrics,
		Input:                  input,
		Time:                   ectx.time,
		Seed:                   ectx.seed,
		InterQueryBuiltinCache: ectx.interQueryBuiltinCache,
		NDBuiltinCache:         ectx.ndBuiltinCache,
		PrintHook:              ectx.printHook,
		Capabilities:           ectx.capabilities,
	})
	if err != nil {
		return nil, err
	}

	parsed, err := ast.ParseTerm(string(result.Result))
	if err != nil {
		return nil, err
	}

	return r.valueToQueryResult(parsed.Value, ectx)
}

func (r *Rego) valueToQueryResult(res ast.Value, ectx *EvalContext) (ResultSet, error) {
	resultSet, ok := res.(ast.Set)
	if !ok {
		return nil, errors.New("illegal result type")
	}

	if resultSet.Len() == 0 {
		return nil, nil
	}

	var rs ResultSet
	err := resultSet.Iter(func(term *ast.Term) error {
		obj, ok := term.Value.(ast.Object)
		if !ok {
			return errors.New("illegal result type")
		}
		qr := topdown.QueryResult{}
		obj.Foreach(func(k, v *ast.Term) {
			kvt := ast.VarTerm(string(k.Value.(ast.String)))
			qr[kvt.Value.(ast.Var)] = v
		})
		result, err := r.generateResult(qr, ectx)
		if err != nil {
			return err
		}
		rs = append(rs, result)
		return nil
	})

	return rs, err
}

func (r *Rego) generateResult(qr topdown.QueryResult, ectx *EvalContext) (Result, error) {

	rewritten := ectx.compiledQuery.compiler.RewrittenVars()

	result := newResult()
	for k, term := range qr {
		if rw, ok := rewritten[k]; ok {
			k = rw
		}
		if isTermVar(k) || isTermWasmVar(k) || k.IsGenerated() || k.IsWildcard() {
			continue
		}

		v, err := r.generateJSON(term, ectx)
		if err != nil {
			return result, err
		}

		result.Bindings[string(k)] = v
	}

	for _, expr := range ectx.compiledQuery.query {
		if expr.Generated {
			continue
		}

		if k, ok := r.capture[expr]; ok {
			v, err := r.generateJSON(qr[k], ectx)
			if err != nil {
				return result, err
			}
			result.Expressions = append(result.Expressions, newExpressionValue(expr, v))
		} else {
			result.Expressions = append(result.Expressions, newExpressionValue(expr, true))
		}

	}
	return result, nil
}

func (r *Rego) partialResult(ctx context.Context, pCfg *PrepareConfig) (PartialResult, error) {

	err := r.prepare(ctx, partialResultQueryType, []extraStage{
		{
			after: "ResolveRefs",
			stage: ast.QueryCompilerStageDefinition{
				Name:       "RewriteForPartialEval",
				MetricName: "query_compile_stage_rewrite_for_partial_eval",
				Stage:      r.rewriteQueryForPartialEval,
			},
		},
	})
	if err != nil {
		return PartialResult{}, err
	}

	ectx := &EvalContext{
		parsedInput:              r.parsedInput,
		metrics:                  r.metrics,
		txn:                      r.txn,
		partialNamespace:         r.partialNamespace,
		queryTracers:             r.queryTracers,
		compiledQuery:            r.compiledQueries[partialResultQueryType],
		instrumentation:          r.instrumentation,
		indexing:                 true,
		resolvers:                r.resolvers,
		capabilities:             r.capabilities,
		strictBuiltinErrors:      r.strictBuiltinErrors,
		nondeterministicBuiltins: r.nondeterministicBuiltins,
	}

	disableInlining := r.disableInlining

	if pCfg.disableInlining != nil {
		disableInlining = *pCfg.disableInlining
	}

	ectx.disableInlining, err = parseStringsToRefs(disableInlining)
	if err != nil {
		return PartialResult{}, err
	}

	pq, err := r.partial(ctx, ectx)
	if err != nil {
		return PartialResult{}, err
	}

	// Construct module for queries.
	id := fmt.Sprintf("__partialresult__%s__", ectx.partialNamespace)

	module, err := ast.ParseModuleWithOpts(id, "package "+ectx.partialNamespace,
		ast.ParserOptions{RegoVersion: r.regoVersion})
	if err != nil {
		return PartialResult{}, errors.New("bad partial namespace")
	}

	module.Rules = make([]*ast.Rule, len(pq.Queries))
	for i, body := range pq.Queries {
		rule := &ast.Rule{
			Head:   ast.NewHead(ast.Var("__result__"), nil, ast.Wildcard),
			Body:   body,
			Module: module,
		}
		module.Rules[i] = rule
		if checkPartialResultForRecursiveRefs(body, rule.Path()) {
			return PartialResult{}, Errors{errPartialEvaluationNotEffective}
		}
	}

	// Update compiler with partial evaluation output.
	r.compiler.Modules[id] = module
	for i, module := range pq.Support {
		r.compiler.Modules[fmt.Sprintf("__partialsupport__%s__%d__", ectx.partialNamespace, i)] = module
	}

	r.metrics.Timer(metrics.RegoModuleCompile).Start()
	r.compilerForTxn(ctx, r.store, r.txn).Compile(r.compiler.Modules)
	r.metrics.Timer(metrics.RegoModuleCompile).Stop()

	if r.compiler.Failed() {
		return PartialResult{}, r.compiler.Errors
	}

	result := PartialResult{
		compiler:     r.compiler,
		store:        r.store,
		body:         ast.MustParseBody(fmt.Sprintf("data.%v.__result__", ectx.partialNamespace)),
		builtinDecls: r.builtinDecls,
		builtinFuncs: r.builtinFuncs,
	}

	return result, nil
}

func (r *Rego) partial(ctx context.Context, ectx *EvalContext) (*PartialQueries, error) {

	var unknowns []*ast.Term

	switch {
	case ectx.parsedUnknowns != nil:
		unknowns = ectx.parsedUnknowns
	case ectx.unknowns != nil:
		unknowns = make([]*ast.Term, len(ectx.unknowns))
		for i := range ectx.unknowns {
			var err error
			unknowns[i], err = ast.ParseTerm(ectx.unknowns[i])
			if err != nil {
				return nil, err
			}
		}
	default:
		// Use input document as unknown if caller has not specified any.
		unknowns = []*ast.Term{ast.NewTerm(ast.InputRootRef)}
	}

	q := topdown.NewQuery(ectx.compiledQuery.query).
		WithQueryCompiler(ectx.compiledQuery.compiler).
		WithCompiler(r.compiler).
		WithStore(r.store).
		WithTransaction(ectx.txn).
		WithBuiltins(r.builtinFuncs).
		WithMetrics(ectx.metrics).
		WithInstrumentation(ectx.instrumentation).
		WithUnknowns(unknowns).
		WithDisableInlining(ectx.disableInlining).
		WithNondeterministicBuiltins(ectx.nondeterministicBuiltins).
		WithRuntime(r.runtime).
		WithIndexing(ectx.indexing).
		WithEarlyExit(ectx.earlyExit).
		WithPartialNamespace(ectx.partialNamespace).
		WithSkipPartialNamespace(r.skipPartialNamespace).
		WithShallowInlining(r.shallowInlining).
		WithInterQueryBuiltinCache(ectx.interQueryBuiltinCache).
		WithInterQueryBuiltinValueCache(ectx.interQueryBuiltinValueCache).
		WithStrictBuiltinErrors(ectx.strictBuiltinErrors).
		WithSeed(ectx.seed).
		WithPrintHook(ectx.printHook)

	if !ectx.time.IsZero() {
		q = q.WithTime(ectx.time)
	}

	if ectx.ndBuiltinCache != nil {
		q = q.WithNDBuiltinCache(ectx.ndBuiltinCache)
	}

	for i := range ectx.queryTracers {
		q = q.WithQueryTracer(ectx.queryTracers[i])
	}

	if ectx.parsedInput != nil {
		q = q.WithInput(ast.NewTerm(ectx.parsedInput))
	}

	for i := range ectx.resolvers {
		q = q.WithResolver(ectx.resolvers[i].ref, ectx.resolvers[i].r)
	}

	// Cancel query if context is cancelled or deadline is reached.
	if ectx.externalCancel == nil {
		// Create a one-off goroutine to handle cancellation for this query.
		c := topdown.NewCancel()
		q = q.WithCancel(c)
		exit := make(chan struct{})
		defer close(exit)
		go waitForDone(ctx, exit, func() {
			c.Cancel()
		})
	} else {
		// Query cancellation is being handled elsewhere.
		q = q.WithCancel(ectx.externalCancel)
	}

	queries, support, err := q.PartialRun(ctx)
	if err != nil {
		return nil, err
	}

	// If the target rego-version is v0, and the rego.v1 import is available, then we attempt to apply it to support modules.
	if r.regoVersion == ast.RegoV0 &&
		(r.capabilities == nil ||
			r.capabilities.ContainsFeature(ast.FeatureRegoV1Import) ||
			r.capabilities.ContainsFeature(ast.FeatureRegoV1)) {

		for i, mod := range support {
			// We can't apply the RegoV0CompatV1 version to the support module if it contains rules or vars that
			// conflict with future keywords.
			applyRegoVersion := true

			ast.WalkRules(mod, func(r *ast.Rule) bool {
				name := r.Head.Name
				if name == "" && len(r.Head.Reference) > 0 {
					name = r.Head.Reference[0].Value.(ast.Var)
				}
				if ast.IsFutureKeywordForRegoVersion(name.String(), ast.RegoV0) {
					applyRegoVersion = false
					return true
				}
				return false
			})

			if applyRegoVersion {
				ast.WalkVars(mod, func(v ast.Var) bool {
					if ast.IsFutureKeywordForRegoVersion(v.String(), ast.RegoV0) {
						applyRegoVersion = false
						return true
					}
					return false
				})
			}

			if applyRegoVersion {
				support[i].SetRegoVersion(ast.RegoV0CompatV1)
			} else {
				support[i].SetRegoVersion(r.regoVersion)
			}
		}
	} else {
		// If the target rego-version is not v0, then we apply the target rego-version to the support modules.
		for i := range support {
			support[i].SetRegoVersion(r.regoVersion)
		}
	}

	pq := &PartialQueries{
		Queries: queries,
		Support: support,
	}

	return pq, nil
}

func (r *Rego) rewriteQueryToCaptureValue(_ ast.QueryCompiler, query ast.Body) (ast.Body, error) {

	checkCapture := iteration(query) || len(query) > 1

	for _, expr := range query {

		if expr.Negated {
			continue
		}

		if expr.IsAssignment() || expr.IsEquality() {
			continue
		}

		var capture *ast.Term

		// If the expression can be evaluated as a function, rewrite it to
		// capture the return value. E.g., neq(1,2) becomes neq(1,2,x) but
		// plus(1,2,x) does not get rewritten.
		switch terms := expr.Terms.(type) {
		case *ast.Term:
			capture = r.generateTermVar()
			expr.Terms = ast.Equality.Expr(terms, capture).Terms
			r.capture[expr] = capture.Value.(ast.Var)
		case []*ast.Term:
			tpe := r.compiler.TypeEnv.Get(terms[0])
			if !types.Void(tpe) && types.Arity(tpe) == len(terms)-1 {
				capture = r.generateTermVar()
				expr.Terms = append(terms, capture)
				r.capture[expr] = capture.Value.(ast.Var)
			}
		}

		if capture != nil && checkCapture {
			cpy := expr.Copy()
			cpy.Terms = capture
			cpy.Generated = true
			cpy.With = nil
			query.Append(cpy)
		}
	}

	return query, nil
}

func (*Rego) rewriteQueryForPartialEval(_ ast.QueryCompiler, query ast.Body) (ast.Body, error) {
	if len(query) != 1 {
		return nil, errors.New("partial evaluation requires single ref (not multiple expressions)")
	}

	term, ok := query[0].Terms.(*ast.Term)
	if !ok {
		return nil, errors.New("partial evaluation requires ref (not expression)")
	}

	ref, ok := term.Value.(ast.Ref)
	if !ok {
		return nil, fmt.Errorf("partial evaluation requires ref (not %v)", ast.ValueName(term.Value))
	}

	if !ref.IsGround() {
		return nil, errors.New("partial evaluation requires ground ref")
	}

	return ast.NewBody(ast.Equality.Expr(ast.Wildcard, term)), nil
}

// rewriteEqualsForPartialQueryCompile will rewrite == to = in queries. Normally
// this wouldn't be done, except for handling queries with the `Partial` API
// where rewriting them can substantially simplify the result, and it is unlikely
// that the caller would need expression values.
func (*Rego) rewriteEqualsForPartialQueryCompile(_ ast.QueryCompiler, query ast.Body) (ast.Body, error) {
	doubleEq := ast.Equal.Ref()
	unifyOp := ast.Equality.Ref()
	ast.WalkExprs(query, func(x *ast.Expr) bool {
		if x.IsCall() {
			operator := x.Operator()
			if operator.Equal(doubleEq) && len(x.Operands()) == 2 {
				x.SetOperator(ast.NewTerm(unifyOp))
			}
		}
		return false
	})
	return query, nil
}

func (r *Rego) generateTermVar() *ast.Term {
	r.termVarID++
	prefix := ast.WildcardPrefix
	if p := r.targetPlugin(r.target); p != nil {
		prefix = wasmVarPrefix
	} else if r.target == targetWasm {
		prefix = wasmVarPrefix
	}
	return ast.VarTerm(fmt.Sprintf("%sterm%v", prefix, r.termVarID))
}

func (r Rego) hasQuery() bool {
	return len(r.query) != 0 || len(r.parsedQuery) != 0
}

func (r Rego) hasWasmModule() bool {
	for _, b := range r.bundles {
		if len(b.WasmModules) > 0 {
			return true
		}
	}
	return false
}

type transactionCloser func(ctx context.Context, err error) error

// getTxn will conditionally create a read or write transaction suitable for
// the configured Rego object. The returned function should be used to close the txn
// regardless of status.
func (r *Rego) getTxn(ctx context.Context) (storage.Transaction, transactionCloser, error) {

	noopCloser := func(_ context.Context, _ error) error {
		return nil // no-op default
	}

	if r.txn != nil {
		// Externally provided txn
		return r.txn, noopCloser, nil
	}

	// Create a new transaction..
	params := storage.TransactionParams{}

	// Bundles and data paths may require writing data files or manifests to storage
	if len(r.bundles) > 0 || len(r.bundlePaths) > 0 || len(r.loadPaths.paths) > 0 {

		// If we were given a store we will *not* write to it, only do that on one
		// which was created automatically on behalf of the user.
		if !r.ownStore {
			return nil, noopCloser, errors.New("unable to start write transaction when store was provided")
		}

		params.Write = true
	}

	txn, err := r.store.NewTransaction(ctx, params)
	if err != nil {
		return nil, noopCloser, err
	}

	// Setup a closer function that will abort or commit as needed.
	closer := func(ctx context.Context, txnErr error) error {
		var err error

		if txnErr == nil && params.Write {
			err = r.store.Commit(ctx, txn)
		} else {
			r.store.Abort(ctx, txn)
		}

		// Clear the auto created transaction now that it is closed.
		r.txn = nil

		return err
	}

	return txn, closer, nil
}

func (r *Rego) compilerForTxn(ctx context.Context, store storage.Store, txn storage.Transaction) *ast.Compiler {
	// Update the compiler to have a valid path conflict check
	// for the current context and transaction.
	return r.compiler.WithPathConflictsCheck(storage.NonEmpty(ctx, store, txn))
}

func checkPartialResultForRecursiveRefs(body ast.Body, path ast.Ref) bool {
	var stop bool
	ast.WalkRefs(body, func(x ast.Ref) bool {
		if !stop {
			if path.HasPrefix(x) {
				stop = true
			}
		}
		return stop
	})
	return stop
}

func isTermVar(v ast.Var) bool {
	return strings.HasPrefix(string(v), ast.WildcardPrefix+"term")
}

func isTermWasmVar(v ast.Var) bool {
	return strings.HasPrefix(string(v), wasmVarPrefix+"term")
}

func waitForDone(ctx context.Context, exit chan struct{}, f func()) {
	select {
	case <-exit:
		return
	case <-ctx.Done():
		f()
		return
	}
}

type rawModule struct {
	filename string
	module   string
}

func (m rawModule) Parse() (*ast.Module, error) {
	return ast.ParseModule(m.filename, m.module)
}

func (m rawModule) ParseWithOpts(opts ast.ParserOptions) (*ast.Module, error) {
	return ast.ParseModuleWithOpts(m.filename, m.module, opts)
}

type extraStage struct {
	after string
	stage ast.QueryCompilerStageDefinition
}

type refResolver struct {
	ref ast.Ref
	r   resolver.Resolver
}

func iteration(x any) bool {

	var stopped bool

	vis := ast.NewGenericVisitor(func(x any) bool {
		switch x := x.(type) {
		case *ast.Term:
			if ast.IsComprehension(x.Value) {
				return true
			}
		case ast.Ref:
			if !stopped {
				if bi := ast.BuiltinMap[x.String()]; bi != nil {
					if bi.Relation {
						stopped = true
						return stopped
					}
				}
				for i := 1; i < len(x); i++ {
					if _, ok := x[i].Value.(ast.Var); ok {
						stopped = true
						return stopped
					}
				}
			}
			return stopped
		}
		return stopped
	})

	vis.Walk(x)

	return stopped
}

func parseStringsToRefs(s []string) ([]ast.Ref, error) {
	if len(s) == 0 {
		return nil, nil
	}

	refs := make([]ast.Ref, len(s))
	for i := range refs {
		var err error
		refs[i], err = ast.ParseRef(s[i])
		if err != nil {
			return nil, err
		}
	}

	return refs, nil
}

// helper function to finish a built-in function call. If an error occurred,
// wrap the error and return it. Otherwise, invoke the iterator if the result
// was defined.
func finishFunction(name string, bctx topdown.BuiltinContext, result *ast.Term, err error, iter func(*ast.Term) error) error {
	if err != nil {
		var e *HaltError
		sb := strings.Builder{}
		if errors.As(err, &e) {
			sb.Grow(len(name) + len(e.Error()) + 2)
			sb.WriteString(name)
			sb.WriteString(": ")
			sb.WriteString(e.Error())
			tdErr := &topdown.Error{
				Code:     topdown.BuiltinErr,
				Message:  sb.String(),
				Location: bctx.Location,
			}
			return topdown.Halt{Err: tdErr.Wrap(e)}
		}
		sb.Grow(len(name) + len(err.Error()) + 2)
		sb.WriteString(name)
		sb.WriteString(": ")
		sb.WriteString(err.Error())
		tdErr := &topdown.Error{
			Code:     topdown.BuiltinErr,
			Message:  sb.String(),
			Location: bctx.Location,
		}
		return tdErr.Wrap(err)
	}
	if result == nil {
		return nil
	}
	return iter(result)
}

// helper function to return an option that sets a custom built-in function.
func newFunction(decl *Function, f topdown.BuiltinFunc) func(*Rego) {
	return func(r *Rego) {
		r.builtinDecls[decl.Name] = &ast.Builtin{
			Name:             decl.Name,
			Decl:             decl.Decl,
			Nondeterministic: decl.Nondeterministic,
		}
		r.builtinFuncs[decl.Name] = &topdown.Builtin{
			Decl: r.builtinDecls[decl.Name],
			Func: f,
		}
	}
}

func generateJSON(term *ast.Term, ectx *EvalContext) (any, error) {
	return ast.JSONWithOpt(term.Value,
		ast.JSONOpt{
			SortSets: ectx.sortSets,
			CopyMaps: ectx.copyMaps,
		})
}

func (r *Rego) planQuery(queries []ast.Body, evalQueryType queryType) (*ir.Policy, error) {
	modules := make([]*ast.Module, 0, len(r.compiler.Modules))
	for _, module := range r.compiler.Modules {
		modules = append(modules, module)
	}

	decls := make(map[string]*ast.Builtin, len(r.builtinDecls)+len(ast.BuiltinMap))
	maps.Copy(decls, ast.BuiltinMap)
	maps.Copy(decls, r.builtinDecls)

	const queryName = "eval" // NOTE(tsandall): the query name is arbitrary

	p := planner.New().
		WithQueries([]planner.QuerySet{
			{
				Name:          queryName,
				Queries:       queries,
				RewrittenVars: r.compiledQueries[evalQueryType].compiler.RewrittenVars(),
			},
		}).
		WithModules(modules).
		WithBuiltinDecls(decls).
		WithDebug(r.dump)

	policy, err := p.Plan()
	if err != nil {
		return nil, err
	}
	if r.dump != nil {
		fmt.Fprintln(r.dump, "PLAN:")
		fmt.Fprintln(r.dump, "-----")
		err = ir.Pretty(r.dump, policy)
		if err != nil {
			return nil, err
		}
		fmt.Fprintln(r.dump)
	}
	return policy, nil
}
