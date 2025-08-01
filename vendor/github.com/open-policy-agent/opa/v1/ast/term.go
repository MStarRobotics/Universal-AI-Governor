// Copyright 2016 The OPA Authors.  All rights reserved.
// Use of this source code is governed by an Apache2
// license that can be found in the LICENSE file.

// nolint: deadcode // Public API.
package ast

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"math/big"
	"net/url"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync"
	"unicode"

	"github.com/cespare/xxhash/v2"
	astJSON "github.com/open-policy-agent/opa/v1/ast/json"
	"github.com/open-policy-agent/opa/v1/ast/location"
	"github.com/open-policy-agent/opa/v1/util"
)

var errFindNotFound = errors.New("find: not found")

// Location records a position in source code.
type Location = location.Location

// NewLocation returns a new Location object.
func NewLocation(text []byte, file string, row int, col int) *Location {
	return location.NewLocation(text, file, row, col)
}

// Value declares the common interface for all Term values. Every kind of Term value
// in the language is represented as a type that implements this interface:
//
// - Null, Boolean, Number, String
// - Object, Array, Set
// - Variables, References
// - Array, Set, and Object Comprehensions
// - Calls
type Value interface {
	Compare(other Value) int      // Compare returns <0, 0, or >0 if this Value is less than, equal to, or greater than other, respectively.
	Find(path Ref) (Value, error) // Find returns value referred to by path or an error if path is not found.
	Hash() int                    // Returns hash code of the value.
	IsGround() bool               // IsGround returns true if this value is not a variable or contains no variables.
	String() string               // String returns a human readable string representation of the value.
}

// InterfaceToValue converts a native Go value x to a Value.
func InterfaceToValue(x any) (Value, error) {
	switch x := x.(type) {
	case Value:
		return x, nil
	case nil:
		return NullValue, nil
	case bool:
		return InternedTerm(x).Value, nil
	case json.Number:
		if interned := InternedIntNumberTermFromString(string(x)); interned != nil {
			return interned.Value, nil
		}
		return Number(x), nil
	case int64:
		return int64Number(x), nil
	case uint64:
		return uint64Number(x), nil
	case float64:
		return floatNumber(x), nil
	case int:
		return intNumber(x), nil
	case string:
		return String(x), nil
	case []any:
		r := util.NewPtrSlice[Term](len(x))
		for i, e := range x {
			e, err := InterfaceToValue(e)
			if err != nil {
				return nil, err
			}
			r[i].Value = e
		}
		return NewArray(r...), nil
	case []string:
		r := util.NewPtrSlice[Term](len(x))
		for i, e := range x {
			r[i].Value = String(e)
		}
		return NewArray(r...), nil
	case map[string]any:
		kvs := util.NewPtrSlice[Term](len(x) * 2)
		idx := 0
		for k, v := range x {
			kvs[idx].Value = String(k)
			v, err := InterfaceToValue(v)
			if err != nil {
				return nil, err
			}
			kvs[idx+1].Value = v
			idx += 2
		}
		tuples := make([][2]*Term, len(kvs)/2)
		for i := 0; i < len(kvs); i += 2 {
			tuples[i/2] = *(*[2]*Term)(kvs[i : i+2])
		}
		return NewObject(tuples...), nil
	case map[string]string:
		r := newobject(len(x))
		for k, v := range x {
			r.Insert(StringTerm(k), StringTerm(v))
		}
		return r, nil
	default:
		ptr := util.Reference(x)
		if err := util.RoundTrip(ptr); err != nil {
			return nil, fmt.Errorf("ast: interface conversion: %w", err)
		}
		return InterfaceToValue(*ptr)
	}
}

// ValueFromReader returns an AST value from a JSON serialized value in the reader.
func ValueFromReader(r io.Reader) (Value, error) {
	var x any
	if err := util.NewJSONDecoder(r).Decode(&x); err != nil {
		return nil, err
	}
	return InterfaceToValue(x)
}

// As converts v into a Go native type referred to by x.
func As(v Value, x any) error {
	return util.NewJSONDecoder(strings.NewReader(v.String())).Decode(x)
}

// Resolver defines the interface for resolving references to native Go values.
type Resolver interface {
	Resolve(Ref) (any, error)
}

// ValueResolver defines the interface for resolving references to AST values.
type ValueResolver interface {
	Resolve(Ref) (Value, error)
}

// UnknownValueErr indicates a ValueResolver was unable to resolve a reference
// because the reference refers to an unknown value.
type UnknownValueErr struct{}

func (UnknownValueErr) Error() string {
	return "unknown value"
}

// IsUnknownValueErr returns true if the err is an UnknownValueErr.
func IsUnknownValueErr(err error) bool {
	_, ok := err.(UnknownValueErr)
	return ok
}

type illegalResolver struct{}

func (illegalResolver) Resolve(ref Ref) (any, error) {
	return nil, fmt.Errorf("illegal value: %v", ref)
}

// ValueToInterface returns the Go representation of an AST value.  The AST
// value should not contain any values that require evaluation (e.g., vars,
// comprehensions, etc.)
func ValueToInterface(v Value, resolver Resolver) (any, error) {
	return valueToInterface(v, resolver, JSONOpt{})
}

func valueToInterface(v Value, resolver Resolver, opt JSONOpt) (any, error) {
	switch v := v.(type) {
	case Null:
		return nil, nil
	case Boolean:
		return bool(v), nil
	case Number:
		return json.Number(v), nil
	case String:
		return string(v), nil
	case *Array:
		buf := []any{}
		for i := range v.Len() {
			x1, err := valueToInterface(v.Elem(i).Value, resolver, opt)
			if err != nil {
				return nil, err
			}
			buf = append(buf, x1)
		}
		return buf, nil
	case *object:
		buf := make(map[string]any, v.Len())
		err := v.Iter(func(k, v *Term) error {
			ki, err := valueToInterface(k.Value, resolver, opt)
			if err != nil {
				return err
			}
			var str string
			var ok bool
			if str, ok = ki.(string); !ok {
				var buf bytes.Buffer
				if err := json.NewEncoder(&buf).Encode(ki); err != nil {
					return err
				}
				str = strings.TrimSpace(buf.String())
			}
			vi, err := valueToInterface(v.Value, resolver, opt)
			if err != nil {
				return err
			}
			buf[str] = vi
			return nil
		})
		if err != nil {
			return nil, err
		}
		return buf, nil
	case *lazyObj:
		if opt.CopyMaps {
			return valueToInterface(v.force(), resolver, opt)
		}
		return v.native, nil
	case Set:
		buf := []any{}
		iter := func(x *Term) error {
			x1, err := valueToInterface(x.Value, resolver, opt)
			if err != nil {
				return err
			}
			buf = append(buf, x1)
			return nil
		}
		var err error
		if opt.SortSets {
			err = v.Sorted().Iter(iter)
		} else {
			err = v.Iter(iter)
		}
		if err != nil {
			return nil, err
		}
		return buf, nil
	case Ref:
		return resolver.Resolve(v)
	default:
		return nil, fmt.Errorf("%v requires evaluation", TypeName(v))
	}
}

// JSON returns the JSON representation of v. The value must not contain any
// refs or terms that require evaluation (e.g., vars, comprehensions, etc.)
func JSON(v Value) (any, error) {
	return JSONWithOpt(v, JSONOpt{})
}

// JSONOpt defines parameters for AST to JSON conversion.
type JSONOpt struct {
	SortSets bool // sort sets before serializing (this makes conversion more expensive)
	CopyMaps bool // enforces copying of map[string]any read from the store
}

// JSONWithOpt returns the JSON representation of v. The value must not contain any
// refs or terms that require evaluation (e.g., vars, comprehensions, etc.)
func JSONWithOpt(v Value, opt JSONOpt) (any, error) {
	return valueToInterface(v, illegalResolver{}, opt)
}

// MustJSON returns the JSON representation of v. The value must not contain any
// refs or terms that require evaluation (e.g., vars, comprehensions, etc.) If
// the conversion fails, this function will panic. This function is mostly for
// test purposes.
func MustJSON(v Value) any {
	r, err := JSON(v)
	if err != nil {
		panic(err)
	}
	return r
}

// MustInterfaceToValue converts a native Go value x to a Value. If the
// conversion fails, this function will panic. This function is mostly for test
// purposes.
func MustInterfaceToValue(x any) Value {
	v, err := InterfaceToValue(x)
	if err != nil {
		panic(err)
	}
	return v
}

// Term is an argument to a function.
type Term struct {
	Value    Value     `json:"value"`              // the value of the Term as represented in Go
	Location *Location `json:"location,omitempty"` // the location of the Term in the source
}

// NewTerm returns a new Term object.
func NewTerm(v Value) *Term {
	return &Term{
		Value: v,
	}
}

// SetLocation updates the term's Location and returns the term itself.
func (term *Term) SetLocation(loc *Location) *Term {
	term.Location = loc
	return term
}

// Loc returns the Location of term.
func (term *Term) Loc() *Location {
	if term == nil {
		return nil
	}
	return term.Location
}

// SetLoc sets the location on term.
func (term *Term) SetLoc(loc *Location) {
	term.SetLocation(loc)
}

// Copy returns a deep copy of term.
func (term *Term) Copy() *Term {
	if term == nil {
		return nil
	}

	cpy := *term

	switch v := term.Value.(type) {
	case Null, Boolean, Number, String, Var:
		cpy.Value = v
	case Ref:
		cpy.Value = v.Copy()
	case *Array:
		cpy.Value = v.Copy()
	case Set:
		cpy.Value = v.Copy()
	case *object:
		cpy.Value = v.Copy()
	case *ArrayComprehension:
		cpy.Value = v.Copy()
	case *ObjectComprehension:
		cpy.Value = v.Copy()
	case *SetComprehension:
		cpy.Value = v.Copy()
	case Call:
		cpy.Value = v.Copy()
	}

	return &cpy
}

// Equal returns true if this term equals the other term. Equality is
// defined for each kind of term, and does not compare the Location.
func (term *Term) Equal(other *Term) bool {
	if term == nil && other != nil {
		return false
	}
	if term != nil && other == nil {
		return false
	}
	if term == other {
		return true
	}

	return ValueEqual(term.Value, other.Value)
}

// Get returns a value referred to by name from the term.
func (term *Term) Get(name *Term) *Term {
	switch v := term.Value.(type) {
	case *object:
		return v.Get(name)
	case *Array:
		return v.Get(name)
	case interface {
		Get(*Term) *Term
	}:
		return v.Get(name)
	case Set:
		if v.Contains(name) {
			return name
		}
	}
	return nil
}

// Hash returns the hash code of the Term's Value. Its Location
// is ignored.
func (term *Term) Hash() int {
	return term.Value.Hash()
}

// IsGround returns true if this term's Value is ground.
func (term *Term) IsGround() bool {
	return term.Value.IsGround()
}

// MarshalJSON returns the JSON encoding of the term.
//
// Specialized marshalling logic is required to include a type hint for Value.
func (term *Term) MarshalJSON() ([]byte, error) {
	d := map[string]any{
		"type":  ValueName(term.Value),
		"value": term.Value,
	}
	jsonOptions := astJSON.GetOptions().MarshalOptions
	if jsonOptions.IncludeLocation.Term {
		if term.Location != nil {
			d["location"] = term.Location
		}
	}
	return json.Marshal(d)
}

func (term *Term) String() string {
	return term.Value.String()
}

// UnmarshalJSON parses the byte array and stores the result in term.
// Specialized unmarshalling is required to handle Value and Location.
func (term *Term) UnmarshalJSON(bs []byte) error {
	v := map[string]any{}
	if err := util.UnmarshalJSON(bs, &v); err != nil {
		return err
	}
	val, err := unmarshalValue(v)
	if err != nil {
		return err
	}
	term.Value = val

	if loc, ok := v["location"].(map[string]any); ok {
		term.Location = &Location{}
		err := unmarshalLocation(term.Location, loc)
		if err != nil {
			return err
		}
	}
	return nil
}

// Vars returns a VarSet with variables contained in this term.
func (term *Term) Vars() VarSet {
	vis := NewVarVisitor()
	vis.Walk(term)
	return vis.vars
}

// IsConstant returns true if the AST value is constant.
func IsConstant(v Value) bool {
	found := false
	vis := GenericVisitor{
		func(x any) bool {
			switch x.(type) {
			case Var, Ref, *ArrayComprehension, *ObjectComprehension, *SetComprehension, Call:
				found = true
				return true
			}
			return false
		},
	}
	vis.Walk(v)
	return !found
}

// IsComprehension returns true if the supplied value is a comprehension.
func IsComprehension(x Value) bool {
	switch x.(type) {
	case *ArrayComprehension, *ObjectComprehension, *SetComprehension:
		return true
	}
	return false
}

// ContainsRefs returns true if the Value v contains refs.
func ContainsRefs(v any) bool {
	found := false
	WalkRefs(v, func(Ref) bool {
		found = true
		return found
	})
	return found
}

// ContainsComprehensions returns true if the Value v contains comprehensions.
func ContainsComprehensions(v any) bool {
	found := false
	WalkClosures(v, func(x any) bool {
		switch x.(type) {
		case *ArrayComprehension, *ObjectComprehension, *SetComprehension:
			found = true
			return found
		}
		return found
	})
	return found
}

// ContainsClosures returns true if the Value v contains closures.
func ContainsClosures(v any) bool {
	found := false
	WalkClosures(v, func(x any) bool {
		switch x.(type) {
		case *ArrayComprehension, *ObjectComprehension, *SetComprehension, *Every:
			found = true
			return found
		}
		return found
	})
	return found
}

// IsScalar returns true if the AST value is a scalar.
func IsScalar(v Value) bool {
	switch v.(type) {
	case String, Number, Boolean, Null:
		return true
	}
	return false
}

// Null represents the null value defined by JSON.
type Null struct{}

var NullValue Value = Null{}

// NullTerm creates a new Term with a Null value.
func NullTerm() *Term {
	return &Term{Value: NullValue}
}

// Equal returns true if the other term Value is also Null.
func (Null) Equal(other Value) bool {
	switch other.(type) {
	case Null:
		return true
	default:
		return false
	}
}

// Compare compares null to other, return <0, 0, or >0 if it is less than, equal to,
// or greater than other.
func (Null) Compare(other Value) int {
	if _, ok := other.(Null); ok {
		return 0
	}
	return -1
}

// Find returns the current value or a not found error.
func (Null) Find(path Ref) (Value, error) {
	if len(path) == 0 {
		return NullValue, nil
	}
	return nil, errFindNotFound
}

// Hash returns the hash code for the Value.
func (Null) Hash() int {
	return 0
}

// IsGround always returns true.
func (Null) IsGround() bool {
	return true
}

func (Null) String() string {
	return "null"
}

// Boolean represents a boolean value defined by JSON.
type Boolean bool

// BooleanTerm creates a new Term with a Boolean value.
func BooleanTerm(b bool) *Term {
	if b {
		return &Term{Value: InternedTerm(true).Value}
	}
	return &Term{Value: InternedTerm(false).Value}
}

// Equal returns true if the other Value is a Boolean and is equal.
func (bol Boolean) Equal(other Value) bool {
	switch other := other.(type) {
	case Boolean:
		return bol == other
	default:
		return false
	}
}

// Compare compares bol to other, return <0, 0, or >0 if it is less than, equal to,
// or greater than other.
func (bol Boolean) Compare(other Value) int {
	switch other := other.(type) {
	case Boolean:
		if bol == other {
			return 0
		}
		if !bol {
			return -1
		}
		return 1
	case Null:
		return 1
	}

	return -1
}

// Find returns the current value or a not found error.
func (bol Boolean) Find(path Ref) (Value, error) {
	if len(path) == 0 {
		return InternedTerm(bool(bol)).Value, nil
	}
	return nil, errFindNotFound
}

// Hash returns the hash code for the Value.
func (bol Boolean) Hash() int {
	if bol {
		return 1
	}
	return 0
}

// IsGround always returns true.
func (Boolean) IsGround() bool {
	return true
}

func (bol Boolean) String() string {
	return strconv.FormatBool(bool(bol))
}

// Number represents a numeric value as defined by JSON.
type Number json.Number

// NumberTerm creates a new Term with a Number value.
func NumberTerm(n json.Number) *Term {
	return &Term{Value: Number(n)}
}

// IntNumberTerm creates a new Term with an integer Number value.
func IntNumberTerm(i int) *Term {
	return &Term{Value: Number(strconv.Itoa(i))}
}

// UIntNumberTerm creates a new Term with an unsigned integer Number value.
func UIntNumberTerm(u uint64) *Term {
	return &Term{Value: uint64Number(u)}
}

// FloatNumberTerm creates a new Term with a floating point Number value.
func FloatNumberTerm(f float64) *Term {
	s := strconv.FormatFloat(f, 'g', -1, 64)
	return &Term{Value: Number(s)}
}

// Equal returns true if the other Value is a Number and is equal.
func (num Number) Equal(other Value) bool {
	switch other := other.(type) {
	case Number:
		if n1, ok1 := num.Int64(); ok1 {
			n2, ok2 := other.Int64()
			if ok1 && ok2 {
				return n1 == n2
			}
		}

		return num.Compare(other) == 0
	default:
		return false
	}
}

// Compare compares num to other, return <0, 0, or >0 if it is less than, equal to,
// or greater than other.
func (num Number) Compare(other Value) int {
	// Optimize for the common case, as calling Compare allocates on heap.
	if otherNum, yes := other.(Number); yes {
		if ai, ok := num.Int64(); ok {
			if bi, ok := otherNum.Int64(); ok {
				if ai == bi {
					return 0
				}
				if ai < bi {
					return -1
				}
				return 1
			}
		}
	}

	return Compare(num, other)
}

// Find returns the current value or a not found error.
func (num Number) Find(path Ref) (Value, error) {
	if len(path) == 0 {
		return num, nil
	}
	return nil, errFindNotFound
}

// Hash returns the hash code for the Value.
func (num Number) Hash() int {
	f, err := json.Number(num).Float64()
	if err != nil {
		bs := []byte(num)
		h := xxhash.Sum64(bs)
		return int(h)
	}
	return int(f)
}

// Int returns the int representation of num if possible.
func (num Number) Int() (int, bool) {
	i64, ok := num.Int64()
	return int(i64), ok
}

// Int64 returns the int64 representation of num if possible.
func (num Number) Int64() (int64, bool) {
	i, err := json.Number(num).Int64()
	if err != nil {
		return 0, false
	}
	return i, true
}

// Float64 returns the float64 representation of num if possible.
func (num Number) Float64() (float64, bool) {
	f, err := json.Number(num).Float64()
	if err != nil {
		return 0, false
	}
	return f, true
}

// IsGround always returns true.
func (Number) IsGround() bool {
	return true
}

// MarshalJSON returns JSON encoded bytes representing num.
func (num Number) MarshalJSON() ([]byte, error) {
	return json.Marshal(json.Number(num))
}

func (num Number) String() string {
	return string(num)
}

func intNumber(i int) Number {
	return Number(strconv.Itoa(i))
}

func int64Number(i int64) Number {
	return Number(strconv.FormatInt(i, 10))
}

func uint64Number(u uint64) Number {
	return Number(strconv.FormatUint(u, 10))
}

func floatNumber(f float64) Number {
	return Number(strconv.FormatFloat(f, 'g', -1, 64))
}

// String represents a string value as defined by JSON.
type String string

// StringTerm creates a new Term with a String value.
func StringTerm(s string) *Term {
	return &Term{Value: String(s)}
}

// Equal returns true if the other Value is a String and is equal.
func (str String) Equal(other Value) bool {
	switch other := other.(type) {
	case String:
		return str == other
	default:
		return false
	}
}

// Compare compares str to other, return <0, 0, or >0 if it is less than, equal to,
// or greater than other.
func (str String) Compare(other Value) int {
	// Optimize for the common case of one string being compared to another by
	// using a direct comparison of values. This avoids the allocation performed
	// when calling Compare and its any argument conversion.
	if otherStr, ok := other.(String); ok {
		if str == otherStr {
			return 0
		}
		if str < otherStr {
			return -1
		}
		return 1
	}

	return Compare(str, other)
}

// Find returns the current value or a not found error.
func (str String) Find(path Ref) (Value, error) {
	if len(path) == 0 {
		return str, nil
	}
	return nil, errFindNotFound
}

// IsGround always returns true.
func (String) IsGround() bool {
	return true
}

func (str String) String() string {
	return strconv.Quote(string(str))
}

// Hash returns the hash code for the Value.
func (str String) Hash() int {
	return int(xxhash.Sum64String(string(str)))
}

// Var represents a variable as defined by the language.
type Var string

// VarTerm creates a new Term with a Variable value.
func VarTerm(v string) *Term {
	return &Term{Value: Var(v)}
}

// Equal returns true if the other Value is a Variable and has the same value
// (name).
func (v Var) Equal(other Value) bool {
	switch other := other.(type) {
	case Var:
		return v == other
	default:
		return false
	}
}

// Compare compares v to other, return <0, 0, or >0 if it is less than, equal to,
// or greater than other.
func (v Var) Compare(other Value) int {
	if otherVar, ok := other.(Var); ok {
		return strings.Compare(string(v), string(otherVar))
	}
	return Compare(v, other)
}

// Find returns the current value or a not found error.
func (v Var) Find(path Ref) (Value, error) {
	if len(path) == 0 {
		return v, nil
	}
	return nil, errFindNotFound
}

// Hash returns the hash code for the Value.
func (v Var) Hash() int {
	return int(xxhash.Sum64String(string(v)))
}

// IsGround always returns false.
func (Var) IsGround() bool {
	return false
}

// IsWildcard returns true if this is a wildcard variable.
func (v Var) IsWildcard() bool {
	return strings.HasPrefix(string(v), WildcardPrefix)
}

// IsGenerated returns true if this variable was generated during compilation.
func (v Var) IsGenerated() bool {
	return strings.HasPrefix(string(v), "__local")
}

func (v Var) String() string {
	// Special case for wildcard so that string representation is parseable. The
	// parser mangles wildcard variables to make their names unique and uses an
	// illegal variable name character (WildcardPrefix) to avoid conflicts. When
	// we serialize the variable here, we need to make sure it's parseable.
	if v.IsWildcard() {
		return Wildcard.String()
	}
	return string(v)
}

// Ref represents a reference as defined by the language.
type Ref []*Term

// EmptyRef returns a new, empty reference.
func EmptyRef() Ref {
	return Ref([]*Term{})
}

// PtrRef returns a new reference against the head for the pointer
// s. Path components in the pointer are unescaped.
func PtrRef(head *Term, s string) (Ref, error) {
	s = strings.Trim(s, "/")
	if s == "" {
		return Ref{head}, nil
	}
	parts := strings.Split(s, "/")
	if maxLen := math.MaxInt32; len(parts) >= maxLen {
		return nil, fmt.Errorf("path too long: %s, %d > %d (max)", s, len(parts), maxLen)
	}
	ref := make(Ref, uint(len(parts))+1)
	ref[0] = head
	for i := range parts {
		var err error
		parts[i], err = url.PathUnescape(parts[i])
		if err != nil {
			return nil, err
		}
		ref[i+1] = StringTerm(parts[i])
	}
	return ref, nil
}

// RefTerm creates a new Term with a Ref value.
func RefTerm(r ...*Term) *Term {
	return &Term{Value: Ref(r)}
}

// Append returns a copy of ref with the term appended to the end.
func (ref Ref) Append(term *Term) Ref {
	n := len(ref)
	dst := make(Ref, n+1)
	copy(dst, ref)
	dst[n] = term
	return dst
}

// Insert returns a copy of the ref with x inserted at pos. If pos < len(ref),
// existing elements are shifted to the right. If pos > len(ref)+1 this
// function panics.
func (ref Ref) Insert(x *Term, pos int) Ref {
	switch {
	case pos == len(ref):
		return ref.Append(x)
	case pos > len(ref)+1:
		panic("illegal index")
	}
	cpy := make(Ref, len(ref)+1)
	copy(cpy, ref[:pos])
	cpy[pos] = x
	copy(cpy[pos+1:], ref[pos:])
	return cpy
}

// Extend returns a copy of ref with the terms from other appended. The head of
// other will be converted to a string.
func (ref Ref) Extend(other Ref) Ref {
	dst := make(Ref, len(ref)+len(other))
	copy(dst, ref)

	head := other[0].Copy()
	head.Value = String(head.Value.(Var))
	offset := len(ref)
	dst[offset] = head

	copy(dst[offset+1:], other[1:])
	return dst
}

// Concat returns a ref with the terms appended.
func (ref Ref) Concat(terms []*Term) Ref {
	if len(terms) == 0 {
		return ref
	}
	cpy := make(Ref, len(ref)+len(terms))
	copy(cpy, ref)
	copy(cpy[len(ref):], terms)
	return cpy
}

// Dynamic returns the offset of the first non-constant operand of ref.
func (ref Ref) Dynamic() int {
	switch ref[0].Value.(type) {
	case Call:
		return 0
	}
	for i := 1; i < len(ref); i++ {
		if !IsConstant(ref[i].Value) {
			return i
		}
	}
	return -1
}

// Copy returns a deep copy of ref.
func (ref Ref) Copy() Ref {
	return termSliceCopy(ref)
}

// CopyNonGround returns a new ref with deep copies of the non-ground parts and shallow
// copies of the ground parts. This is a *much* cheaper operation than Copy for operations
// that only intend to modify (e.g. plug) the non-ground parts. The head element of the ref
// is always shallow copied.
func (ref Ref) CopyNonGround() Ref {
	cpy := make(Ref, len(ref))
	cpy[0] = ref[0]

	for i := 1; i < len(ref); i++ {
		if ref[i].Value.IsGround() {
			cpy[i] = ref[i]
		} else {
			cpy[i] = ref[i].Copy()
		}
	}

	return cpy
}

// Equal returns true if ref is equal to other.
func (ref Ref) Equal(other Value) bool {
	switch o := other.(type) {
	case Ref:
		if len(ref) == len(o) {
			for i := range ref {
				if !ref[i].Equal(o[i]) {
					return false
				}
			}

			return true
		}
	}

	return false
}

// Compare compares ref to other, return <0, 0, or >0 if it is less than, equal to,
// or greater than other.
func (ref Ref) Compare(other Value) int {
	if o, ok := other.(Ref); ok {
		return termSliceCompare(ref, o)
	}

	return Compare(ref, other)
}

// Find returns the current value or a "not found" error.
func (ref Ref) Find(path Ref) (Value, error) {
	if len(path) == 0 {
		return ref, nil
	}
	return nil, errFindNotFound
}

// Hash returns the hash code for the Value.
func (ref Ref) Hash() int {
	return termSliceHash(ref)
}

// HasPrefix returns true if the other ref is a prefix of this ref.
func (ref Ref) HasPrefix(other Ref) bool {
	if len(other) > len(ref) {
		return false
	}
	for i := range other {
		if !ref[i].Equal(other[i]) {
			return false
		}
	}
	return true
}

// ConstantPrefix returns the constant portion of the ref starting from the head.
func (ref Ref) ConstantPrefix() Ref {
	i := ref.Dynamic()
	if i < 0 {
		return ref.Copy()
	}
	return ref[:i].Copy()
}

func (ref Ref) StringPrefix() Ref {
	for i := 1; i < len(ref); i++ {
		switch ref[i].Value.(type) {
		case String: // pass
		default: // cut off
			return ref[:i].Copy()
		}
	}

	return ref.Copy()
}

// GroundPrefix returns the ground portion of the ref starting from the head. By
// definition, the head of the reference is always ground.
func (ref Ref) GroundPrefix() Ref {
	if ref.IsGround() {
		return ref
	}

	prefix := make(Ref, 0, len(ref))

	for i, x := range ref {
		if i > 0 && !x.IsGround() {
			break
		}
		prefix = append(prefix, x)
	}

	return prefix
}

func (ref Ref) DynamicSuffix() Ref {
	i := ref.Dynamic()
	if i < 0 {
		return nil
	}
	return ref[i:]
}

// IsGround returns true if all of the parts of the Ref are ground.
func (ref Ref) IsGround() bool {
	if len(ref) == 0 {
		return true
	}
	return termSliceIsGround(ref[1:])
}

// IsNested returns true if this ref contains other Refs.
func (ref Ref) IsNested() bool {
	for _, x := range ref {
		if _, ok := x.Value.(Ref); ok {
			return true
		}
	}
	return false
}

// Ptr returns a slash-separated path string for this ref. If the ref
// contains non-string terms this function returns an error. Path
// components are escaped.
func (ref Ref) Ptr() (string, error) {
	parts := make([]string, 0, len(ref)-1)
	for _, term := range ref[1:] {
		if str, ok := term.Value.(String); ok {
			parts = append(parts, url.PathEscape(string(str)))
		} else {
			return "", errors.New("invalid path value type")
		}
	}
	return strings.Join(parts, "/"), nil
}

var varRegexp = regexp.MustCompile("^[[:alpha:]_][[:alpha:][:digit:]_]*$")

func IsVarCompatibleString(s string) bool {
	return varRegexp.MatchString(s)
}

func (ref Ref) String() string {
	if len(ref) == 0 {
		return ""
	}

	if len(ref) == 1 {
		switch p := ref[0].Value.(type) {
		case Var:
			return p.String()
		}
	}

	sb := sbPool.Get()
	defer sbPool.Put(sb)

	sb.Grow(10 * len(ref))
	sb.WriteString(ref[0].Value.String())

	for _, p := range ref[1:] {
		switch p := p.Value.(type) {
		case String:
			str := string(p)
			if varRegexp.MatchString(str) && !IsKeyword(str) {
				sb.WriteByte('.')
				sb.WriteString(str)
			} else {
				sb.WriteByte('[')
				// Determine whether we need the full JSON-escaped form
				if strings.ContainsFunc(str, isControlOrBackslash) {
					// only now pay the cost of expensive JSON-escaped form
					sb.WriteString(p.String())
				} else {
					sb.WriteByte('"')
					sb.WriteString(str)
					sb.WriteByte('"')
				}
				sb.WriteByte(']')
			}
		default:
			sb.WriteByte('[')
			sb.WriteString(p.String())
			sb.WriteByte(']')
		}
	}

	return sb.String()
}

// OutputVars returns a VarSet containing variables that would be bound by evaluating
// this expression in isolation.
func (ref Ref) OutputVars() VarSet {
	vis := NewVarVisitor().WithParams(VarVisitorParams{SkipRefHead: true})
	vis.WalkRef(ref)
	return vis.Vars()
}

func (ref Ref) toArray() *Array {
	terms := make([]*Term, 0, len(ref))
	for _, term := range ref {
		if _, ok := term.Value.(String); ok {
			terms = append(terms, term)
		} else {
			terms = append(terms, InternedTerm(term.Value.String()))
		}
	}
	return NewArray(terms...)
}

// QueryIterator defines the interface for querying AST documents with references.
type QueryIterator func(map[Var]Value, Value) error

// ArrayTerm creates a new Term with an Array value.
func ArrayTerm(a ...*Term) *Term {
	return NewTerm(NewArray(a...))
}

// NewArray creates an Array with the terms provided. The array will
// use the provided term slice.
func NewArray(a ...*Term) *Array {
	hs := make([]int, len(a))
	for i, e := range a {
		hs[i] = e.Value.Hash()
	}
	arr := &Array{elems: a, hashs: hs, ground: termSliceIsGround(a)}
	arr.rehash()
	return arr
}

// Array represents an array as defined by the language. Arrays are similar to the
// same types as defined by JSON with the exception that they can contain Vars
// and References.
type Array struct {
	elems  []*Term
	hashs  []int // element hashes
	hash   int
	ground bool
}

// Copy returns a deep copy of arr.
func (arr *Array) Copy() *Array {
	cpy := make([]int, len(arr.elems))
	copy(cpy, arr.hashs)
	return &Array{
		elems:  termSliceCopy(arr.elems),
		hashs:  cpy,
		hash:   arr.hash,
		ground: arr.IsGround()}
}

// Equal returns true if arr is equal to other.
func (arr *Array) Equal(other Value) bool {
	if arr == other {
		return true
	}

	if other, ok := other.(*Array); ok && len(arr.elems) == len(other.elems) {
		for i := range arr.elems {
			if !arr.elems[i].Equal(other.elems[i]) {
				return false
			}
		}
		return true
	}

	return false
}

// Compare compares arr to other, return <0, 0, or >0 if it is less than, equal to,
// or greater than other.
func (arr *Array) Compare(other Value) int {
	if b, ok := other.(*Array); ok {
		return termSliceCompare(arr.elems, b.elems)
	}

	sortA := sortOrder(arr)
	sortB := sortOrder(other)

	if sortA < sortB {
		return -1
	} else if sortB < sortA {
		return 1
	}

	return Compare(arr, other)
}

// Find returns the value at the index or an out-of-range error.
func (arr *Array) Find(path Ref) (Value, error) {
	if len(path) == 0 {
		return arr, nil
	}
	num, ok := path[0].Value.(Number)
	if !ok {
		return nil, errFindNotFound
	}
	i, ok := num.Int()
	if !ok {
		return nil, errFindNotFound
	}
	if i < 0 || i >= arr.Len() {
		return nil, errFindNotFound
	}

	term := arr.Elem(i)
	// Using Find on scalar values costs an allocation (type -> Value conversion)
	// and since we already have the Value here, we can avoid that.
	if len(path) == 1 && IsScalar(term.Value) {
		return term.Value, nil
	}

	return term.Value.Find(path[1:])
}

// Get returns the element at pos or nil if not possible.
func (arr *Array) Get(pos *Term) *Term {
	num, ok := pos.Value.(Number)
	if !ok {
		return nil
	}

	i, ok := num.Int()
	if !ok {
		return nil
	}

	if i >= 0 && i < len(arr.elems) {
		return arr.elems[i]
	}

	return nil
}

// Sorted returns a new Array that contains the sorted elements of arr.
func (arr *Array) Sorted() *Array {
	cpy := make([]*Term, len(arr.elems))
	for i := range cpy {
		cpy[i] = arr.elems[i]
	}

	slices.SortFunc(cpy, TermValueCompare)

	a := NewArray(cpy...)
	a.hashs = arr.hashs
	return a
}

// Hash returns the hash code for the Value.
func (arr *Array) Hash() int {
	return arr.hash
}

// IsGround returns true if all of the Array elements are ground.
func (arr *Array) IsGround() bool {
	return arr.ground
}

// MarshalJSON returns JSON encoded bytes representing arr.
func (arr *Array) MarshalJSON() ([]byte, error) {
	if len(arr.elems) == 0 {
		return []byte(`[]`), nil
	}
	return json.Marshal(arr.elems)
}

func (arr *Array) String() string {
	sb := sbPool.Get()
	sb.Grow(len(arr.elems) * 16)

	defer sbPool.Put(sb)

	sb.WriteByte('[')
	for i, e := range arr.elems {
		if i > 0 {
			sb.WriteString(", ")
		}
		sb.WriteString(e.String())
	}
	sb.WriteByte(']')

	return sb.String()
}

// Len returns the number of elements in the array.
func (arr *Array) Len() int {
	return len(arr.elems)
}

// Elem returns the element i of arr.
func (arr *Array) Elem(i int) *Term {
	return arr.elems[i]
}

// Set sets the element i of arr.
func (arr *Array) Set(i int, v *Term) {
	arr.set(i, v)
}

// rehash updates the cached hash of arr.
func (arr *Array) rehash() {
	arr.hash = 0
	for _, h := range arr.hashs {
		arr.hash += h
	}
}

// set sets the element i of arr.
func (arr *Array) set(i int, v *Term) {
	arr.ground = arr.ground && v.IsGround()
	arr.elems[i] = v
	arr.hashs[i] = v.Value.Hash()
	arr.rehash()
}

// Slice returns a slice of arr starting from i index to j. -1
// indicates the end of the array. The returned value array is not a
// copy and any modifications to either of arrays may be reflected to
// the other.
func (arr *Array) Slice(i, j int) *Array {
	var elems []*Term
	var hashs []int
	if j == -1 {
		elems = arr.elems[i:]
		hashs = arr.hashs[i:]
	} else {
		elems = arr.elems[i:j]
		hashs = arr.hashs[i:j]
	}
	// If arr is ground, the slice is, too.
	// If it's not, the slice could still be.
	gr := arr.ground || termSliceIsGround(elems)

	s := &Array{elems: elems, hashs: hashs, ground: gr}
	s.rehash()
	return s
}

// Iter calls f on each element in arr. If f returns an error,
// iteration stops and the return value is the error.
func (arr *Array) Iter(f func(*Term) error) error {
	for i := range arr.elems {
		if err := f(arr.elems[i]); err != nil {
			return err
		}
	}
	return nil
}

// Until calls f on each element in arr. If f returns true, iteration stops.
func (arr *Array) Until(f func(*Term) bool) bool {
	return slices.ContainsFunc(arr.elems, f)
}

// Foreach calls f on each element in arr.
func (arr *Array) Foreach(f func(*Term)) {
	for _, term := range arr.elems {
		f(term)
	}
}

// Append appends a term to arr, returning the appended array.
func (arr *Array) Append(v *Term) *Array {
	cpy := *arr
	cpy.elems = append(arr.elems, v)
	cpy.hashs = append(arr.hashs, v.Value.Hash())
	cpy.hash = arr.hash + v.Value.Hash()
	cpy.ground = arr.ground && v.IsGround()
	return &cpy
}

// Set represents a set as defined by the language.
type Set interface {
	Value
	Len() int
	Copy() Set
	Diff(Set) Set
	Intersect(Set) Set
	Union(Set) Set
	Add(*Term)
	Iter(func(*Term) error) error
	Until(func(*Term) bool) bool
	Foreach(func(*Term))
	Contains(*Term) bool
	Map(func(*Term) (*Term, error)) (Set, error)
	Reduce(*Term, func(*Term, *Term) (*Term, error)) (*Term, error)
	Sorted() *Array
	Slice() []*Term
}

// NewSet returns a new Set containing t.
func NewSet(t ...*Term) Set {
	s := newset(len(t))
	for _, term := range t {
		s.insert(term, false)
	}
	return s
}

func newset(n int) *set {
	var keys []*Term
	if n > 0 {
		keys = make([]*Term, 0, n)
	}
	return &set{
		elems:     make(map[int]*Term, n),
		keys:      keys,
		hash:      0,
		ground:    true,
		sortGuard: sync.Once{},
	}
}

// SetTerm returns a new Term representing a set containing terms t.
func SetTerm(t ...*Term) *Term {
	set := NewSet(t...)
	return &Term{
		Value: set,
	}
}

type set struct {
	elems  map[int]*Term
	keys   []*Term
	hash   int
	ground bool
	// Prevents race condition around sorting.
	// We can avoid (the allocation cost of) using a pointer here as all
	// methods of `set` use a pointer receiver, and the `sync.Once` value
	// is never copied.
	sortGuard sync.Once
}

// Copy returns a deep copy of s.
func (s *set) Copy() Set {
	terms := make([]*Term, len(s.keys))
	for i := range s.keys {
		terms[i] = s.keys[i].Copy()
	}
	cpy := NewSet(terms...).(*set)
	cpy.hash = s.hash
	cpy.ground = s.ground
	return cpy
}

// IsGround returns true if all terms in s are ground.
func (s *set) IsGround() bool {
	return s.ground
}

// Hash returns a hash code for s.
func (s *set) Hash() int {
	return s.hash
}

func (s *set) String() string {
	if s.Len() == 0 {
		return "set()"
	}

	sb := sbPool.Get()
	sb.Grow(s.Len() * 16)

	defer sbPool.Put(sb)

	sb.WriteByte('{')
	for i := range s.sortedKeys() {
		if i > 0 {
			sb.WriteString(", ")
		}
		sb.WriteString(s.keys[i].Value.String())
	}
	sb.WriteByte('}')

	return sb.String()
}

func (s *set) sortedKeys() []*Term {
	s.sortGuard.Do(func() {
		slices.SortFunc(s.keys, TermValueCompare)
	})
	return s.keys
}

// Compare compares s to other, return <0, 0, or >0 if it is less than, equal to,
// or greater than other.
func (s *set) Compare(other Value) int {
	o1 := sortOrder(s)
	o2 := sortOrder(other)
	if o1 < o2 {
		return -1
	} else if o1 > o2 {
		return 1
	}
	t := other.(*set)
	return termSliceCompare(s.sortedKeys(), t.sortedKeys())
}

// Find returns the set or dereferences the element itself.
func (s *set) Find(path Ref) (Value, error) {
	if len(path) == 0 {
		return s, nil
	}
	if !s.Contains(path[0]) {
		return nil, errFindNotFound
	}
	return path[0].Value.Find(path[1:])
}

// Diff returns elements in s that are not in other.
func (s *set) Diff(other Set) Set {
	if s.Compare(other) == 0 {
		return NewSet()
	}

	terms := make([]*Term, 0, len(s.keys))
	for _, term := range s.sortedKeys() {
		if !other.Contains(term) {
			terms = append(terms, term)
		}
	}

	return NewSet(terms...)
}

// Intersect returns the set containing elements in both s and other.
func (s *set) Intersect(other Set) Set {
	o := other.(*set)
	n, m := s.Len(), o.Len()
	ss := s
	so := o
	if m < n {
		ss = o
		so = s
		n = m
	}

	terms := make([]*Term, 0, n)
	for _, term := range ss.sortedKeys() {
		if so.Contains(term) {
			terms = append(terms, term)
		}
	}

	return NewSet(terms...)
}

// Union returns the set containing all elements of s and other.
func (s *set) Union(other Set) Set {
	r := NewSet()
	s.Foreach(r.Add)
	other.Foreach(r.Add)
	return r
}

// Add updates s to include t.
func (s *set) Add(t *Term) {
	s.insert(t, true)
}

// Iter calls f on each element in s. If f returns an error, iteration stops
// and the return value is the error.
func (s *set) Iter(f func(*Term) error) error {
	for _, term := range s.sortedKeys() {
		if err := f(term); err != nil {
			return err
		}
	}
	return nil
}

// Until calls f on each element in s. If f returns true, iteration stops.
func (s *set) Until(f func(*Term) bool) bool {
	return slices.ContainsFunc(s.sortedKeys(), f)
}

// Foreach calls f on each element in s.
func (s *set) Foreach(f func(*Term)) {
	for _, term := range s.sortedKeys() {
		f(term)
	}
}

// Map returns a new Set obtained by applying f to each value in s.
func (s *set) Map(f func(*Term) (*Term, error)) (Set, error) {
	mapped := make([]*Term, 0, len(s.keys))
	for _, x := range s.sortedKeys() {
		term, err := f(x)
		if err != nil {
			return nil, err
		}
		mapped = append(mapped, term)
	}
	return NewSet(mapped...), nil
}

// Reduce returns a Term produced by applying f to each value in s. The first
// argument to f is the reduced value (starting with i) and the second argument
// to f is the element in s.
func (s *set) Reduce(i *Term, f func(*Term, *Term) (*Term, error)) (*Term, error) {
	err := s.Iter(func(x *Term) error {
		var err error
		i, err = f(i, x)
		if err != nil {
			return err
		}
		return nil
	})
	return i, err
}

// Contains returns true if t is in s.
func (s *set) Contains(t *Term) bool {
	return s.get(t) != nil
}

// Len returns the number of elements in the set.
func (s *set) Len() int {
	return len(s.keys)
}

// MarshalJSON returns JSON encoded bytes representing s.
func (s *set) MarshalJSON() ([]byte, error) {
	if s.keys == nil {
		return []byte(`[]`), nil
	}
	return json.Marshal(s.sortedKeys())
}

// Sorted returns an Array that contains the sorted elements of s.
func (s *set) Sorted() *Array {
	cpy := make([]*Term, len(s.keys))
	copy(cpy, s.sortedKeys())
	return NewArray(cpy...)
}

// Slice returns a slice of terms contained in the set.
func (s *set) Slice() []*Term {
	return s.sortedKeys()
}

// NOTE(philipc): We assume a many-readers, single-writer model here.
// This method should NOT be used concurrently, or else we risk data races.
func (s *set) insert(x *Term, resetSortGuard bool) {
	hash := x.Hash()
	insertHash := hash
	// This `equal` utility is duplicated and manually inlined a number of
	// time in this file.  Inlining it avoids heap allocations, so it makes
	// a big performance difference: some operations like lookup become twice
	// as slow without it.
	var equal func(v Value) bool

	switch x := x.Value.(type) {
	case Null, Boolean, String, Var:
		equal = func(y Value) bool { return x == y }
	case Number:
		if xi, err := json.Number(x).Int64(); err == nil {
			equal = func(y Value) bool {
				if y, ok := y.(Number); ok {
					if yi, err := json.Number(y).Int64(); err == nil {
						return xi == yi
					}
				}

				return false
			}
			break
		}

		// We use big.Rat for comparing big numbers.
		// It replaces big.Float due to following reason:
		// big.Float comes with a default precision of 64, and setting a
		// larger precision results in more memory being allocated
		// (regardless of the actual number we are parsing with SetString).
		//
		// Note: If we're so close to zero that big.Float says we are zero, do
		// *not* big.Rat).SetString on the original string it'll potentially
		// take very long.
		var a *big.Rat
		fa, ok := new(big.Float).SetString(string(x))
		if !ok {
			panic("illegal value")
		}
		if fa.IsInt() {
			if i, _ := fa.Int64(); i == 0 {
				a = new(big.Rat).SetInt64(0)
			}
		}
		if a == nil {
			a, ok = new(big.Rat).SetString(string(x))
			if !ok {
				panic("illegal value")
			}
		}

		equal = func(b Value) bool {
			if bNum, ok := b.(Number); ok {
				var b *big.Rat
				fb, ok := new(big.Float).SetString(string(bNum))
				if !ok {
					panic("illegal value")
				}
				if fb.IsInt() {
					if i, _ := fb.Int64(); i == 0 {
						b = new(big.Rat).SetInt64(0)
					}
				}
				if b == nil {
					b, ok = new(big.Rat).SetString(string(bNum))
					if !ok {
						panic("illegal value")
					}
				}

				return a.Cmp(b) == 0
			}

			return false
		}
	default:
		equal = func(y Value) bool { return Compare(x, y) == 0 }
	}

	for curr, ok := s.elems[insertHash]; ok; {
		if equal(curr.Value) {
			return
		}

		insertHash++
		curr, ok = s.elems[insertHash]
	}

	s.elems[insertHash] = x
	// O(1) insertion, but we'll have to re-sort the keys later.
	s.keys = append(s.keys, x)

	if resetSortGuard {
		// Reset the sync.Once instance.
		// See https://github.com/golang/go/issues/25955 for why we do it this way.
		// Note that this will always be the case when external code calls insert via
		// Add, or otherwise. Internal code may however benefit from not having to
		// re-create this pointer when it's known not to be needed.
		s.sortGuard = sync.Once{}
	}

	s.hash += hash
	s.ground = s.ground && x.IsGround()
}

func (s *set) get(x *Term) *Term {
	hash := x.Hash()
	// This `equal` utility is duplicated and manually inlined a number of
	// time in this file.  Inlining it avoids heap allocations, so it makes
	// a big performance difference: some operations like lookup become twice
	// as slow without it.
	var equal func(v Value) bool

	switch x := x.Value.(type) {
	case Null, Boolean, String, Var:
		equal = func(y Value) bool { return x == y }
	case Number:
		if xi, err := json.Number(x).Int64(); err == nil {
			equal = func(y Value) bool {
				if y, ok := y.(Number); ok {
					if yi, err := json.Number(y).Int64(); err == nil {
						return xi == yi
					}
				}

				return false
			}
			break
		}

		// We use big.Rat for comparing big numbers.
		// It replaces big.Float due to following reason:
		// big.Float comes with a default precision of 64, and setting a
		// larger precision results in more memory being allocated
		// (regardless of the actual number we are parsing with SetString).
		//
		// Note: If we're so close to zero that big.Float says we are zero, do
		// *not* big.Rat).SetString on the original string it'll potentially
		// take very long.
		var a *big.Rat
		fa, ok := new(big.Float).SetString(string(x))
		if !ok {
			panic("illegal value")
		}
		if fa.IsInt() {
			if i, _ := fa.Int64(); i == 0 {
				a = new(big.Rat).SetInt64(0)
			}
		}
		if a == nil {
			a, ok = new(big.Rat).SetString(string(x))
			if !ok {
				panic("illegal value")
			}
		}

		equal = func(b Value) bool {
			if bNum, ok := b.(Number); ok {
				var b *big.Rat
				fb, ok := new(big.Float).SetString(string(bNum))
				if !ok {
					panic("illegal value")
				}
				if fb.IsInt() {
					if i, _ := fb.Int64(); i == 0 {
						b = new(big.Rat).SetInt64(0)
					}
				}
				if b == nil {
					b, ok = new(big.Rat).SetString(string(bNum))
					if !ok {
						panic("illegal value")
					}
				}

				return a.Cmp(b) == 0
			}
			return false

		}

	default:
		equal = func(y Value) bool { return Compare(x, y) == 0 }
	}

	for curr, ok := s.elems[hash]; ok; {
		if equal(curr.Value) {
			return curr
		}

		hash++
		curr, ok = s.elems[hash]
	}
	return nil
}

// Object represents an object as defined by the language.
type Object interface {
	Value
	Len() int
	Get(*Term) *Term
	Copy() Object
	Insert(*Term, *Term)
	Iter(func(*Term, *Term) error) error
	Until(func(*Term, *Term) bool) bool
	Foreach(func(*Term, *Term))
	Map(func(*Term, *Term) (*Term, *Term, error)) (Object, error)
	Diff(other Object) Object
	Intersect(other Object) [][3]*Term
	Merge(other Object) (Object, bool)
	MergeWith(other Object, conflictResolver func(v1, v2 *Term) (*Term, bool)) (Object, bool)
	Filter(filter Object) (Object, error)
	Keys() []*Term
	KeysIterator() ObjectKeysIterator
	get(k *Term) *objectElem // To prevent external implementations
}

// NewObject creates a new Object with t.
func NewObject(t ...[2]*Term) Object {
	obj := newobject(len(t))
	for i := range t {
		obj.insert(t[i][0], t[i][1], false)
	}
	return obj
}

// ObjectTerm creates a new Term with an Object value.
func ObjectTerm(o ...[2]*Term) *Term {
	return &Term{Value: NewObject(o...)}
}

func LazyObject(blob map[string]any) Object {
	return &lazyObj{native: blob, cache: map[string]Value{}}
}

type lazyObj struct {
	strict Object
	cache  map[string]Value
	native map[string]any
}

func (l *lazyObj) force() Object {
	if l.strict == nil {
		l.strict = MustInterfaceToValue(l.native).(Object)
		// NOTE(jf): a possible performance improvement here would be to check how many
		// entries have been realized to AST in the cache, and if some threshold compared to the
		// total number of keys is exceeded, realize the remaining entries and set l.strict to l.cache.
		l.cache = map[string]Value{} // We don't need the cache anymore; drop it to free up memory.
	}
	return l.strict
}

func (l *lazyObj) Compare(other Value) int {
	o1 := sortOrder(l)
	o2 := sortOrder(other)
	if o1 < o2 {
		return -1
	} else if o2 < o1 {
		return 1
	}
	return l.force().Compare(other)
}

func (l *lazyObj) Copy() Object {
	return l
}

func (l *lazyObj) Diff(other Object) Object {
	return l.force().Diff(other)
}

func (l *lazyObj) Intersect(other Object) [][3]*Term {
	return l.force().Intersect(other)
}

func (l *lazyObj) Iter(f func(*Term, *Term) error) error {
	return l.force().Iter(f)
}

func (l *lazyObj) Until(f func(*Term, *Term) bool) bool {
	// NOTE(sr): there could be benefits in not forcing here -- if we abort because
	// `f` returns true, we could save us from converting the rest of the object.
	return l.force().Until(f)
}

func (l *lazyObj) Foreach(f func(*Term, *Term)) {
	l.force().Foreach(f)
}

func (l *lazyObj) Filter(filter Object) (Object, error) {
	return l.force().Filter(filter)
}

func (l *lazyObj) Map(f func(*Term, *Term) (*Term, *Term, error)) (Object, error) {
	return l.force().Map(f)
}

func (l *lazyObj) MarshalJSON() ([]byte, error) {
	return l.force().(*object).MarshalJSON()
}

func (l *lazyObj) Merge(other Object) (Object, bool) {
	return l.force().Merge(other)
}

func (l *lazyObj) MergeWith(other Object, conflictResolver func(v1, v2 *Term) (*Term, bool)) (Object, bool) {
	return l.force().MergeWith(other, conflictResolver)
}

func (l *lazyObj) Len() int {
	return len(l.native)
}

func (l *lazyObj) String() string {
	return l.force().String()
}

// get is merely there to implement the Object interface -- `get` there serves the
// purpose of prohibiting external implementations. It's never called for lazyObj.
func (*lazyObj) get(*Term) *objectElem {
	return nil
}

func (l *lazyObj) Get(k *Term) *Term {
	if l.strict != nil {
		return l.strict.Get(k)
	}
	if s, ok := k.Value.(String); ok {
		if v, ok := l.cache[string(s)]; ok {
			return NewTerm(v)
		}

		if val, ok := l.native[string(s)]; ok {
			var converted Value
			switch val := val.(type) {
			case map[string]any:
				converted = LazyObject(val)
			default:
				converted = MustInterfaceToValue(val)
			}
			l.cache[string(s)] = converted
			return NewTerm(converted)
		}
	}
	return nil
}

func (l *lazyObj) Insert(k, v *Term) {
	l.force().Insert(k, v)
}

func (*lazyObj) IsGround() bool {
	return true
}

func (l *lazyObj) Hash() int {
	return l.force().Hash()
}

func (l *lazyObj) Keys() []*Term {
	if l.strict != nil {
		return l.strict.Keys()
	}
	ret := make([]*Term, 0, len(l.native))
	for k := range l.native {
		ret = append(ret, StringTerm(k))
	}
	slices.SortFunc(ret, TermValueCompare)

	return ret
}

func (l *lazyObj) KeysIterator() ObjectKeysIterator {
	return &lazyObjKeysIterator{keys: l.Keys()}
}

type lazyObjKeysIterator struct {
	current int
	keys    []*Term
}

func (ki *lazyObjKeysIterator) Next() (*Term, bool) {
	if ki.current == len(ki.keys) {
		return nil, false
	}
	ki.current++
	return ki.keys[ki.current-1], true
}

func (l *lazyObj) Find(path Ref) (Value, error) {
	if l.strict != nil {
		return l.strict.Find(path)
	}
	if len(path) == 0 {
		return l, nil
	}
	if p0, ok := path[0].Value.(String); ok {
		if v, ok := l.cache[string(p0)]; ok {
			return v.Find(path[1:])
		}

		if v, ok := l.native[string(p0)]; ok {
			var converted Value
			switch v := v.(type) {
			case map[string]any:
				converted = LazyObject(v)
			default:
				converted = MustInterfaceToValue(v)
			}
			l.cache[string(p0)] = converted
			return converted.Find(path[1:])
		}
	}
	return nil, errFindNotFound
}

type object struct {
	elems  map[int]*objectElem
	keys   objectElemSlice
	ground int // number of key and value grounds. Counting is
	// required to support insert's key-value replace.
	hash      int
	sortGuard sync.Once // Prevents race condition around sorting.
}

func newobject(n int) *object {
	var keys objectElemSlice
	if n > 0 {
		keys = make(objectElemSlice, 0, n)
	}
	return &object{
		elems:     make(map[int]*objectElem, n),
		keys:      keys,
		ground:    0,
		hash:      0,
		sortGuard: sync.Once{},
	}
}

type objectElem struct {
	key   *Term
	value *Term
	next  *objectElem
}

type objectElemSlice []*objectElem

func (s objectElemSlice) Less(i, j int) bool { return Compare(s[i].key.Value, s[j].key.Value) < 0 }
func (s objectElemSlice) Swap(i, j int)      { s[i], s[j] = s[j], s[i] }
func (s objectElemSlice) Len() int           { return len(s) }

// Item is a helper for constructing an tuple containing two Terms
// representing a key/value pair in an Object.
func Item(key, value *Term) [2]*Term {
	return [2]*Term{key, value}
}

func (obj *object) sortedKeys() objectElemSlice {
	obj.sortGuard.Do(func() {
		slices.SortFunc(obj.keys, func(a, b *objectElem) int {
			return a.key.Value.Compare(b.key.Value)
		})
	})
	return obj.keys
}

// Compare compares obj to other, return <0, 0, or >0 if it is less than, equal to,
// or greater than other.
func (obj *object) Compare(other Value) int {
	if x, ok := other.(*lazyObj); ok {
		other = x.force()
	}
	o1 := sortOrder(obj)
	o2 := sortOrder(other)
	if o1 < o2 {
		return -1
	} else if o2 < o1 {
		return 1
	}
	a := obj
	b := other.(*object)
	// Ensure that keys are in canonical sorted order before use!
	akeys := a.sortedKeys()
	bkeys := b.sortedKeys()
	minLen := len(akeys)
	if len(b.keys) < len(akeys) {
		minLen = len(bkeys)
	}
	for i := range minLen {
		keysCmp := Compare(akeys[i].key, bkeys[i].key)
		if keysCmp < 0 {
			return -1
		}
		if keysCmp > 0 {
			return 1
		}
		valA := akeys[i].value
		valB := bkeys[i].value
		valCmp := Compare(valA, valB)
		if valCmp != 0 {
			return valCmp
		}
	}
	if len(akeys) < len(bkeys) {
		return -1
	}
	if len(bkeys) < len(akeys) {
		return 1
	}
	return 0
}

// Find returns the value at the key or undefined.
func (obj *object) Find(path Ref) (Value, error) {
	if len(path) == 0 {
		return obj, nil
	}
	term := obj.Get(path[0])
	if term == nil {
		return nil, errFindNotFound
	}
	// Using Find on scalar values costs an allocation (type -> Value conversion)
	// and since we already have the Value here, we can avoid that.
	if len(path) == 1 && IsScalar(term.Value) {
		return term.Value, nil
	}

	return term.Value.Find(path[1:])
}

func (obj *object) Insert(k, v *Term) {
	obj.insert(k, v, true)
}

// Get returns the value of k in obj if k exists, otherwise nil.
func (obj *object) Get(k *Term) *Term {
	if elem := obj.get(k); elem != nil {
		return elem.value
	}
	return nil
}

// Hash returns the hash code for the Value.
func (obj *object) Hash() int {
	return obj.hash
}

// IsGround returns true if all of the Object key/value pairs are ground.
func (obj *object) IsGround() bool {
	return obj.ground == 2*len(obj.keys)
}

// Copy returns a deep copy of obj.
func (obj *object) Copy() Object {
	cpy, _ := obj.Map(func(k, v *Term) (*Term, *Term, error) {
		return k.Copy(), v.Copy(), nil
	})
	cpy.(*object).hash = obj.hash
	return cpy
}

// Diff returns a new Object that contains only the key/value pairs that exist in obj.
func (obj *object) Diff(other Object) Object {
	r := newobject(obj.Len())
	for _, node := range obj.sortedKeys() {
		if other.Get(node.key) == nil {
			r.insert(node.key, node.value, false)
		}
	}
	return r
}

// Intersect returns a slice of term triplets that represent the intersection of keys
// between obj and other. For each intersecting key, the values from obj and other are included
// as the last two terms in the triplet (respectively).
func (obj *object) Intersect(other Object) [][3]*Term {
	r := [][3]*Term{}
	obj.Foreach(func(k, v *Term) {
		if v2 := other.Get(k); v2 != nil {
			r = append(r, [3]*Term{k, v, v2})
		}
	})
	return r
}

// Iter calls the function f for each key-value pair in the object. If f
// returns an error, iteration stops and the error is returned.
func (obj *object) Iter(f func(*Term, *Term) error) error {
	for _, node := range obj.sortedKeys() {
		if err := f(node.key, node.value); err != nil {
			return err
		}
	}
	return nil
}

// Until calls f for each key-value pair in the object. If f returns
// true, iteration stops and Until returns true. Otherwise, return
// false.
func (obj *object) Until(f func(*Term, *Term) bool) bool {
	for _, node := range obj.sortedKeys() {
		if f(node.key, node.value) {
			return true
		}
	}
	return false
}

// Foreach calls f for each key-value pair in the object.
func (obj *object) Foreach(f func(*Term, *Term)) {
	for _, node := range obj.sortedKeys() {
		f(node.key, node.value)
	}
}

// Map returns a new Object constructed by mapping each element in the object
// using the function f. If f returns an error, the error is returned by Map.
// If f return a nil key, the element is skipped.
func (obj *object) Map(f func(*Term, *Term) (*Term, *Term, error)) (Object, error) {
	cpy := newobject(obj.Len())
	for _, node := range obj.sortedKeys() {
		k, v, err := f(node.key, node.value)
		if err != nil {
			return nil, err
		}
		if k != nil {
			cpy.insert(k, v, false)
		}
	}
	return cpy, nil
}

// Keys returns the keys of obj.
func (obj *object) Keys() []*Term {
	keys := make([]*Term, len(obj.keys))

	for i, elem := range obj.sortedKeys() {
		keys[i] = elem.key
	}

	return keys
}

// Returns an iterator over the obj's keys.
func (obj *object) KeysIterator() ObjectKeysIterator {
	return newobjectKeysIterator(obj)
}

// MarshalJSON returns JSON encoded bytes representing obj.
func (obj *object) MarshalJSON() ([]byte, error) {
	sl := make([][2]*Term, obj.Len())
	for i, node := range obj.sortedKeys() {
		sl[i] = Item(node.key, node.value)
	}
	return json.Marshal(sl)
}

// Merge returns a new Object containing the non-overlapping keys of obj and other. If there are
// overlapping keys between obj and other, the values of associated with the keys are merged. Only
// objects can be merged with other objects. If the values cannot be merged, the second turn value
// will be false.
func (obj *object) Merge(other Object) (Object, bool) {
	return obj.MergeWith(other, func(v1, v2 *Term) (*Term, bool) {
		obj1, ok1 := v1.Value.(Object)
		obj2, ok2 := v2.Value.(Object)
		if !ok1 || !ok2 {
			return nil, true
		}
		obj3, ok := obj1.Merge(obj2)
		if !ok {
			return nil, true
		}
		return NewTerm(obj3), false
	})
}

// MergeWith returns a new Object containing the merged keys of obj and other.
// If there are overlapping keys between obj and other, the conflictResolver
// is called. The conflictResolver can return a merged value and a boolean
// indicating if the merge has failed and should stop.
func (obj *object) MergeWith(other Object, conflictResolver func(v1, v2 *Term) (*Term, bool)) (Object, bool) {
	result := NewObject()
	stop := obj.Until(func(k, v *Term) bool {
		v2 := other.Get(k)
		// The key didn't exist in other, keep the original value
		if v2 == nil {
			result.Insert(k, v)
			return false
		}

		// The key exists in both, resolve the conflict if possible
		merged, stop := conflictResolver(v, v2)
		if !stop {
			result.Insert(k, merged)
		}
		return stop
	})

	if stop {
		return nil, false
	}

	// Copy in any values from other for keys that don't exist in obj
	other.Foreach(func(k, v *Term) {
		if v2 := obj.Get(k); v2 == nil {
			result.Insert(k, v)
		}
	})
	return result, true
}

// Filter returns a new object from values in obj where the keys are
// found in filter. Array indices for values can be specified as
// number strings.
func (obj *object) Filter(filter Object) (Object, error) {
	filtered, err := filterObject(obj, filter)
	if err != nil {
		return nil, err
	}
	return filtered.(Object), nil
}

// Len returns the number of elements in the object.
func (obj *object) Len() int {
	return len(obj.keys)
}

func (obj *object) String() string {
	sb := sbPool.Get()
	sb.Grow(obj.Len() * 32)

	defer sbPool.Put(sb)

	sb.WriteByte('{')

	for i, elem := range obj.sortedKeys() {
		if i > 0 {
			sb.WriteString(", ")
		}
		sb.WriteString(elem.key.String())
		sb.WriteString(": ")
		sb.WriteString(elem.value.String())
	}
	sb.WriteByte('}')

	return sb.String()
}

func (obj *object) get(k *Term) *objectElem {
	hash := k.Hash()

	// This `equal` utility is duplicated and manually inlined a number of
	// time in this file.  Inlining it avoids heap allocations, so it makes
	// a big performance difference: some operations like lookup become twice
	// as slow without it.
	var equal func(v Value) bool

	switch x := k.Value.(type) {
	case Null, Boolean, String, Var:
		equal = func(y Value) bool { return x == y }
	case Number:
		if xi, ok := x.Int64(); ok {
			equal = func(y Value) bool {
				if y, ok := y.(Number); ok {
					if yi, ok := y.Int64(); ok {
						return xi == yi
					}
				}

				return false
			}
			break
		}

		// We use big.Rat for comparing big numbers.
		// It replaces big.Float due to following reason:
		// big.Float comes with a default precision of 64, and setting a
		// larger precision results in more memory being allocated
		// (regardless of the actual number we are parsing with SetString).
		//
		// Note: If we're so close to zero that big.Float says we are zero, do
		// *not* big.Rat).SetString on the original string it'll potentially
		// take very long.
		var a *big.Rat
		fa, ok := new(big.Float).SetString(string(x))
		if !ok {
			panic("illegal value")
		}
		if fa.IsInt() {
			if i, _ := fa.Int64(); i == 0 {
				a = new(big.Rat).SetInt64(0)
			}
		}
		if a == nil {
			a, ok = new(big.Rat).SetString(string(x))
			if !ok {
				panic("illegal value")
			}
		}

		equal = func(b Value) bool {
			if bNum, ok := b.(Number); ok {
				var b *big.Rat
				fb, ok := new(big.Float).SetString(string(bNum))
				if !ok {
					panic("illegal value")
				}
				if fb.IsInt() {
					if i, _ := fb.Int64(); i == 0 {
						b = new(big.Rat).SetInt64(0)
					}
				}
				if b == nil {
					b, ok = new(big.Rat).SetString(string(bNum))
					if !ok {
						panic("illegal value")
					}
				}

				return a.Cmp(b) == 0
			}

			return false
		}
	default:
		equal = func(y Value) bool { return Compare(x, y) == 0 }
	}

	for curr := obj.elems[hash]; curr != nil; curr = curr.next {
		if equal(curr.key.Value) {
			return curr
		}
	}
	return nil
}

// NOTE(philipc): We assume a many-readers, single-writer model here.
// This method should NOT be used concurrently, or else we risk data races.
func (obj *object) insert(k, v *Term, resetSortGuard bool) {
	hash := k.Hash()
	head := obj.elems[hash]
	// This `equal` utility is duplicated and manually inlined a number of
	// time in this file.  Inlining it avoids heap allocations, so it makes
	// a big performance difference: some operations like lookup become twice
	// as slow without it.
	var equal func(v Value) bool

	switch x := k.Value.(type) {
	case Null, Boolean, String, Var:
		equal = func(y Value) bool { return x == y }
	case Number:
		if xi, err := json.Number(x).Int64(); err == nil {
			equal = func(y Value) bool {
				if y, ok := y.(Number); ok {
					if yi, err := json.Number(y).Int64(); err == nil {
						return xi == yi
					}
				}

				return false
			}
			break
		}

		// We use big.Rat for comparing big numbers.
		// It replaces big.Float due to following reason:
		// big.Float comes with a default precision of 64, and setting a
		// larger precision results in more memory being allocated
		// (regardless of the actual number we are parsing with SetString).
		//
		// Note: If we're so close to zero that big.Float says we are zero, do
		// *not* big.Rat).SetString on the original string it'll potentially
		// take very long.
		var a *big.Rat
		fa, ok := new(big.Float).SetString(string(x))
		if !ok {
			panic("illegal value")
		}
		if fa.IsInt() {
			if i, _ := fa.Int64(); i == 0 {
				a = new(big.Rat).SetInt64(0)
			}
		}
		if a == nil {
			a, ok = new(big.Rat).SetString(string(x))
			if !ok {
				panic("illegal value")
			}
		}

		equal = func(b Value) bool {
			if bNum, ok := b.(Number); ok {
				var b *big.Rat
				fb, ok := new(big.Float).SetString(string(bNum))
				if !ok {
					panic("illegal value")
				}
				if fb.IsInt() {
					if i, _ := fb.Int64(); i == 0 {
						b = new(big.Rat).SetInt64(0)
					}
				}
				if b == nil {
					b, ok = new(big.Rat).SetString(string(bNum))
					if !ok {
						panic("illegal value")
					}
				}

				return a.Cmp(b) == 0
			}

			return false
		}
	default:
		equal = func(y Value) bool { return Compare(x, y) == 0 }
	}

	for curr := head; curr != nil; curr = curr.next {
		if equal(curr.key.Value) {
			// The ground bit of the value may change in
			// replace, hence adjust the counter per old
			// and new value.

			if curr.value.IsGround() {
				obj.ground--
			}
			if v.IsGround() {
				obj.ground++
			}

			curr.value = v

			obj.rehash()
			return
		}
	}
	elem := &objectElem{
		key:   k,
		value: v,
		next:  head,
	}
	obj.elems[hash] = elem
	// O(1) insertion, but we'll have to re-sort the keys later.
	obj.keys = append(obj.keys, elem)

	if resetSortGuard {
		// Reset the sync.Once instance.
		// See https://github.com/golang/go/issues/25955 for why we do it this way.
		// Note that this will always be the case when external code calls insert via
		// Add, or otherwise. Internal code may however benefit from not having to
		// re-create this when it's known not to be needed.
		obj.sortGuard = sync.Once{}
	}

	obj.hash += hash + v.Hash()

	if k.IsGround() {
		obj.ground++
	}
	if v.IsGround() {
		obj.ground++
	}
}

func (obj *object) rehash() {
	// obj.keys is considered truth, from which obj.hash and obj.elems are recalculated.

	obj.hash = 0
	obj.elems = make(map[int]*objectElem, len(obj.keys))

	for _, elem := range obj.keys {
		hash := elem.key.Hash()
		obj.hash += hash + elem.value.Hash()
		obj.elems[hash] = elem
	}
}

func filterObject(o Value, filter Value) (Value, error) {
	if (Null{}).Equal(filter) {
		return o, nil
	}

	filteredObj, ok := filter.(*object)
	if !ok {
		return nil, fmt.Errorf("invalid filter value %q, expected an object", filter)
	}

	switch v := o.(type) {
	case String, Number, Boolean, Null:
		return o, nil
	case *Array:
		values := NewArray()
		for i := range v.Len() {
			subFilter := filteredObj.Get(InternedIntegerString(i))
			if subFilter != nil {
				filteredValue, err := filterObject(v.Elem(i).Value, subFilter.Value)
				if err != nil {
					return nil, err
				}
				values = values.Append(NewTerm(filteredValue))
			}
		}
		return values, nil
	case Set:
		terms := make([]*Term, 0, v.Len())
		for _, t := range v.Slice() {
			if filteredObj.Get(t) != nil {
				filteredValue, err := filterObject(t.Value, filteredObj.Get(t).Value)
				if err != nil {
					return nil, err
				}
				terms = append(terms, NewTerm(filteredValue))
			}
		}
		return NewSet(terms...), nil
	case *object:
		values := NewObject()

		iterObj := v
		other := filteredObj
		if v.Len() < filteredObj.Len() {
			iterObj = filteredObj
			other = v
		}

		err := iterObj.Iter(func(key *Term, _ *Term) error {
			if other.Get(key) != nil {
				filteredValue, err := filterObject(v.Get(key).Value, filteredObj.Get(key).Value)
				if err != nil {
					return err
				}
				values.Insert(key, NewTerm(filteredValue))
			}
			return nil
		})
		return values, err
	default:
		return nil, fmt.Errorf("invalid object value type %q", v)
	}
}

// NOTE(philipc): The only way to get an ObjectKeyIterator should be
// from an Object. This ensures that the iterator can have implementation-
// specific details internally, with no contracts except to the very
// limited interface.
type ObjectKeysIterator interface {
	Next() (*Term, bool)
}

type objectKeysIterator struct {
	obj     *object
	numKeys int
	index   int
}

func newobjectKeysIterator(o *object) ObjectKeysIterator {
	return &objectKeysIterator{
		obj:     o,
		numKeys: o.Len(),
		index:   0,
	}
}

func (oki *objectKeysIterator) Next() (*Term, bool) {
	if oki.index == oki.numKeys || oki.numKeys == 0 {
		return nil, false
	}
	oki.index++
	return oki.obj.sortedKeys()[oki.index-1].key, true
}

// ArrayComprehension represents an array comprehension as defined in the language.
type ArrayComprehension struct {
	Term *Term `json:"term"`
	Body Body  `json:"body"`
}

// ArrayComprehensionTerm creates a new Term with an ArrayComprehension value.
func ArrayComprehensionTerm(term *Term, body Body) *Term {
	return &Term{
		Value: &ArrayComprehension{
			Term: term,
			Body: body,
		},
	}
}

// Copy returns a deep copy of ac.
func (ac *ArrayComprehension) Copy() *ArrayComprehension {
	cpy := *ac
	cpy.Body = ac.Body.Copy()
	cpy.Term = ac.Term.Copy()
	return &cpy
}

// Equal returns true if ac is equal to other.
func (ac *ArrayComprehension) Equal(other Value) bool {
	return Compare(ac, other) == 0
}

// Compare compares ac to other, return <0, 0, or >0 if it is less than, equal to,
// or greater than other.
func (ac *ArrayComprehension) Compare(other Value) int {
	return Compare(ac, other)
}

// Find returns the current value or a not found error.
func (ac *ArrayComprehension) Find(path Ref) (Value, error) {
	if len(path) == 0 {
		return ac, nil
	}
	return nil, errFindNotFound
}

// Hash returns the hash code of the Value.
func (ac *ArrayComprehension) Hash() int {
	return ac.Term.Hash() + ac.Body.Hash()
}

// IsGround returns true if the Term and Body are ground.
func (ac *ArrayComprehension) IsGround() bool {
	return ac.Term.IsGround() && ac.Body.IsGround()
}

func (ac *ArrayComprehension) String() string {
	return "[" + ac.Term.String() + " | " + ac.Body.String() + "]"
}

// ObjectComprehension represents an object comprehension as defined in the language.
type ObjectComprehension struct {
	Key   *Term `json:"key"`
	Value *Term `json:"value"`
	Body  Body  `json:"body"`
}

// ObjectComprehensionTerm creates a new Term with an ObjectComprehension value.
func ObjectComprehensionTerm(key, value *Term, body Body) *Term {
	return &Term{
		Value: &ObjectComprehension{
			Key:   key,
			Value: value,
			Body:  body,
		},
	}
}

// Copy returns a deep copy of oc.
func (oc *ObjectComprehension) Copy() *ObjectComprehension {
	cpy := *oc
	cpy.Body = oc.Body.Copy()
	cpy.Key = oc.Key.Copy()
	cpy.Value = oc.Value.Copy()
	return &cpy
}

// Equal returns true if oc is equal to other.
func (oc *ObjectComprehension) Equal(other Value) bool {
	return Compare(oc, other) == 0
}

// Compare compares oc to other, return <0, 0, or >0 if it is less than, equal to,
// or greater than other.
func (oc *ObjectComprehension) Compare(other Value) int {
	return Compare(oc, other)
}

// Find returns the current value or a not found error.
func (oc *ObjectComprehension) Find(path Ref) (Value, error) {
	if len(path) == 0 {
		return oc, nil
	}
	return nil, errFindNotFound
}

// Hash returns the hash code of the Value.
func (oc *ObjectComprehension) Hash() int {
	return oc.Key.Hash() + oc.Value.Hash() + oc.Body.Hash()
}

// IsGround returns true if the Key, Value and Body are ground.
func (oc *ObjectComprehension) IsGround() bool {
	return oc.Key.IsGround() && oc.Value.IsGround() && oc.Body.IsGround()
}

func (oc *ObjectComprehension) String() string {
	return "{" + oc.Key.String() + ": " + oc.Value.String() + " | " + oc.Body.String() + "}"
}

// SetComprehension represents a set comprehension as defined in the language.
type SetComprehension struct {
	Term *Term `json:"term"`
	Body Body  `json:"body"`
}

// SetComprehensionTerm creates a new Term with an SetComprehension value.
func SetComprehensionTerm(term *Term, body Body) *Term {
	return &Term{
		Value: &SetComprehension{
			Term: term,
			Body: body,
		},
	}
}

// Copy returns a deep copy of sc.
func (sc *SetComprehension) Copy() *SetComprehension {
	cpy := *sc
	cpy.Body = sc.Body.Copy()
	cpy.Term = sc.Term.Copy()
	return &cpy
}

// Equal returns true if sc is equal to other.
func (sc *SetComprehension) Equal(other Value) bool {
	return Compare(sc, other) == 0
}

// Compare compares sc to other, return <0, 0, or >0 if it is less than, equal to,
// or greater than other.
func (sc *SetComprehension) Compare(other Value) int {
	return Compare(sc, other)
}

// Find returns the current value or a not found error.
func (sc *SetComprehension) Find(path Ref) (Value, error) {
	if len(path) == 0 {
		return sc, nil
	}
	return nil, errFindNotFound
}

// Hash returns the hash code of the Value.
func (sc *SetComprehension) Hash() int {
	return sc.Term.Hash() + sc.Body.Hash()
}

// IsGround returns true if the Term and Body are ground.
func (sc *SetComprehension) IsGround() bool {
	return sc.Term.IsGround() && sc.Body.IsGround()
}

func (sc *SetComprehension) String() string {
	return "{" + sc.Term.String() + " | " + sc.Body.String() + "}"
}

// Call represents as function call in the language.
type Call []*Term

// CallTerm returns a new Term with a Call value defined by terms. The first
// term is the operator and the rest are operands.
func CallTerm(terms ...*Term) *Term {
	return NewTerm(Call(terms))
}

// Copy returns a deep copy of c.
func (c Call) Copy() Call {
	return termSliceCopy(c)
}

// Compare compares c to other, return <0, 0, or >0 if it is less than, equal to,
// or greater than other.
func (c Call) Compare(other Value) int {
	return Compare(c, other)
}

// Find returns the current value or a not found error.
func (Call) Find(Ref) (Value, error) {
	return nil, errFindNotFound
}

// Hash returns the hash code for the Value.
func (c Call) Hash() int {
	return termSliceHash(c)
}

// IsGround returns true if the Value is ground.
func (c Call) IsGround() bool {
	return termSliceIsGround(c)
}

// MakeExpr returns an ew Expr from this call.
func (c Call) MakeExpr(output *Term) *Expr {
	terms := []*Term(c)
	return NewExpr(append(terms, output))
}

func (c Call) String() string {
	args := make([]string, len(c)-1)
	for i := 1; i < len(c); i++ {
		args[i-1] = c[i].String()
	}
	return fmt.Sprintf("%v(%v)", c[0], strings.Join(args, ", "))
}

func termSliceCopy(a []*Term) []*Term {
	cpy := make([]*Term, len(a))
	for i := range a {
		cpy[i] = a[i].Copy()
	}
	return cpy
}

func termSliceEqual(a, b []*Term) bool {
	if len(a) == len(b) {
		for i := range a {
			if !a[i].Equal(b[i]) {
				return false
			}
		}
		return true
	}
	return false
}

func termSliceHash(a []*Term) int {
	var hash int
	for _, v := range a {
		hash += v.Value.Hash()
	}
	return hash
}

func termSliceIsGround(a []*Term) bool {
	for _, v := range a {
		if !v.IsGround() {
			return false
		}
	}
	return true
}

// Detect when String() need to use expensive JSON‐escaped form
func isControlOrBackslash(r rune) bool {
	return r == '\\' || unicode.IsControl(r)
}

// NOTE(tsandall): The unmarshalling errors in these functions are not
// helpful for callers because they do not identify the source of the
// unmarshalling error. Because OPA doesn't accept JSON describing ASTs
// from callers, this is acceptable (for now). If that changes in the future,
// the error messages should be revisited. The current approach focuses
// on the happy path and treats all errors the same. If better error
// reporting is needed, the error paths will need to be fleshed out.

func unmarshalBody(b []any) (Body, error) {
	buf := Body{}
	for _, e := range b {
		if m, ok := e.(map[string]any); ok {
			expr := &Expr{}
			if err := unmarshalExpr(expr, m); err == nil {
				buf = append(buf, expr)
				continue
			}
		}
		goto unmarshal_error
	}
	return buf, nil
unmarshal_error:
	return nil, errors.New("ast: unable to unmarshal body")
}

func unmarshalExpr(expr *Expr, v map[string]any) error {
	if x, ok := v["negated"]; ok {
		if b, ok := x.(bool); ok {
			expr.Negated = b
		} else {
			return fmt.Errorf("ast: unable to unmarshal negated field with type: %T (expected true or false)", v["negated"])
		}
	}
	if generatedRaw, ok := v["generated"]; ok {
		if b, ok := generatedRaw.(bool); ok {
			expr.Generated = b
		} else {
			return fmt.Errorf("ast: unable to unmarshal generated field with type: %T (expected true or false)", v["generated"])
		}
	}

	if err := unmarshalExprIndex(expr, v); err != nil {
		return err
	}
	switch ts := v["terms"].(type) {
	case map[string]any:
		t, err := unmarshalTerm(ts)
		if err != nil {
			return err
		}
		expr.Terms = t
	case []any:
		terms, err := unmarshalTermSlice(ts)
		if err != nil {
			return err
		}
		expr.Terms = terms
	default:
		return fmt.Errorf(`ast: unable to unmarshal terms field with type: %T (expected {"value": ..., "type": ...} or [{"value": ..., "type": ...}, ...])`, v["terms"])
	}
	if x, ok := v["with"]; ok {
		if sl, ok := x.([]any); ok {
			ws := make([]*With, len(sl))
			for i := range sl {
				var err error
				ws[i], err = unmarshalWith(sl[i])
				if err != nil {
					return err
				}
			}
			expr.With = ws
		}
	}
	if loc, ok := v["location"].(map[string]any); ok {
		expr.Location = &Location{}
		if err := unmarshalLocation(expr.Location, loc); err != nil {
			return err
		}
	}
	return nil
}

func unmarshalLocation(loc *Location, v map[string]any) error {
	if x, ok := v["file"]; ok {
		if s, ok := x.(string); ok {
			loc.File = s
		} else {
			return fmt.Errorf("ast: unable to unmarshal file field with type: %T (expected string)", v["file"])
		}
	}
	if x, ok := v["row"]; ok {
		if n, ok := x.(json.Number); ok {
			i64, err := n.Int64()
			if err != nil {
				return err
			}
			loc.Row = int(i64)
		} else {
			return fmt.Errorf("ast: unable to unmarshal row field with type: %T (expected number)", v["row"])
		}
	}
	if x, ok := v["col"]; ok {
		if n, ok := x.(json.Number); ok {
			i64, err := n.Int64()
			if err != nil {
				return err
			}
			loc.Col = int(i64)
		} else {
			return fmt.Errorf("ast: unable to unmarshal col field with type: %T (expected number)", v["col"])
		}
	}

	return nil
}

func unmarshalExprIndex(expr *Expr, v map[string]any) error {
	if x, ok := v["index"]; ok {
		if n, ok := x.(json.Number); ok {
			i, err := n.Int64()
			if err == nil {
				expr.Index = int(i)
				return nil
			}
		}
	}
	return fmt.Errorf("ast: unable to unmarshal index field with type: %T (expected integer)", v["index"])
}

func unmarshalTerm(m map[string]any) (*Term, error) {
	var term Term

	v, err := unmarshalValue(m)
	if err != nil {
		return nil, err
	}
	term.Value = v

	if loc, ok := m["location"].(map[string]any); ok {
		term.Location = &Location{}
		if err := unmarshalLocation(term.Location, loc); err != nil {
			return nil, err
		}
	}

	return &term, nil
}

func unmarshalTermSlice(s []any) ([]*Term, error) {
	buf := []*Term{}
	for _, x := range s {
		if m, ok := x.(map[string]any); ok {
			t, err := unmarshalTerm(m)
			if err == nil {
				buf = append(buf, t)
				continue
			}
			return nil, err
		}
		return nil, errors.New("ast: unable to unmarshal term")
	}
	return buf, nil
}

func unmarshalTermSliceValue(d map[string]any) ([]*Term, error) {
	if s, ok := d["value"].([]any); ok {
		return unmarshalTermSlice(s)
	}
	return nil, errors.New(`ast: unable to unmarshal term (expected {"value": [...], "type": ...} where type is one of: ref, array, or set)`)
}

func unmarshalWith(i any) (*With, error) {
	if m, ok := i.(map[string]any); ok {
		tgt, _ := m["target"].(map[string]any)
		target, err := unmarshalTerm(tgt)
		if err == nil {
			val, _ := m["value"].(map[string]any)
			value, err := unmarshalTerm(val)
			if err == nil {
				return &With{
					Target: target,
					Value:  value,
				}, nil
			}
			return nil, err
		}
		return nil, err
	}
	return nil, errors.New(`ast: unable to unmarshal with modifier (expected {"target": {...}, "value": {...}})`)
}

func unmarshalValue(d map[string]any) (Value, error) {
	v := d["value"]
	switch d["type"] {
	case "null":
		return NullValue, nil
	case "boolean":
		if b, ok := v.(bool); ok {
			return Boolean(b), nil
		}
	case "number":
		if n, ok := v.(json.Number); ok {
			return Number(n), nil
		}
	case "string":
		if s, ok := v.(string); ok {
			return String(s), nil
		}
	case "var":
		if s, ok := v.(string); ok {
			return Var(s), nil
		}
	case "ref":
		if s, err := unmarshalTermSliceValue(d); err == nil {
			return Ref(s), nil
		}
	case "array":
		if s, err := unmarshalTermSliceValue(d); err == nil {
			return NewArray(s...), nil
		}
	case "set":
		if s, err := unmarshalTermSliceValue(d); err == nil {
			return NewSet(s...), nil
		}
	case "object":
		if s, ok := v.([]any); ok {
			buf := NewObject()
			for _, x := range s {
				if i, ok := x.([]any); ok && len(i) == 2 {
					p, err := unmarshalTermSlice(i)
					if err == nil {
						buf.Insert(p[0], p[1])
						continue
					}
				}
				goto unmarshal_error
			}
			return buf, nil
		}
	case "arraycomprehension", "setcomprehension":
		if m, ok := v.(map[string]any); ok {
			t, ok := m["term"].(map[string]any)
			if !ok {
				goto unmarshal_error
			}

			term, err := unmarshalTerm(t)
			if err != nil {
				goto unmarshal_error
			}

			b, ok := m["body"].([]any)
			if !ok {
				goto unmarshal_error
			}

			body, err := unmarshalBody(b)
			if err != nil {
				goto unmarshal_error
			}

			if d["type"] == "arraycomprehension" {
				return &ArrayComprehension{Term: term, Body: body}, nil
			}
			return &SetComprehension{Term: term, Body: body}, nil
		}
	case "objectcomprehension":
		if m, ok := v.(map[string]any); ok {
			k, ok := m["key"].(map[string]any)
			if !ok {
				goto unmarshal_error
			}

			key, err := unmarshalTerm(k)
			if err != nil {
				goto unmarshal_error
			}

			v, ok := m["value"].(map[string]any)
			if !ok {
				goto unmarshal_error
			}

			value, err := unmarshalTerm(v)
			if err != nil {
				goto unmarshal_error
			}

			b, ok := m["body"].([]any)
			if !ok {
				goto unmarshal_error
			}

			body, err := unmarshalBody(b)
			if err != nil {
				goto unmarshal_error
			}

			return &ObjectComprehension{Key: key, Value: value, Body: body}, nil
		}
	case "call":
		if s, err := unmarshalTermSliceValue(d); err == nil {
			return Call(s), nil
		}
	}
unmarshal_error:
	return nil, errors.New("ast: unable to unmarshal term")
}
