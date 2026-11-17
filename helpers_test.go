package fts0001

import (
	"bytes"
	"cmp"
	"errors"
	"fmt"
	"log/slog"
	"reflect"
	"regexp"
	"strings"
	"testing"
	"time"
)

// The assertion helpers the tests use. assert reports and carries on;
// require stops the test. Kept to what this package's tests call, so
// the module has no dependency outside the standard library.

type assertions struct{ fatal bool }

var (
	assert  = assertions{fatal: false}
	require = assertions{fatal: true}
)

func (a assertions) fail(t testing.TB, what string, msgAndArgs []any) bool {
	t.Helper()
	if len(msgAndArgs) > 0 {
		if format, ok := msgAndArgs[0].(string); ok {
			what += ": " + fmt.Sprintf(format, msgAndArgs[1:]...)
		} else {
			what += ": " + fmt.Sprint(msgAndArgs...)
		}
	}
	if a.fatal {
		t.Fatal(what)
	} else {
		t.Error(what)
	}
	return false
}

func (a assertions) Contains(t testing.TB, haystack, needle any, msgAndArgs ...any) bool {
	t.Helper()
	hv := reflect.ValueOf(haystack)
	switch hv.Kind() {
	case reflect.String:
		if n, ok := needle.(string); ok && strings.Contains(hv.String(), n) {
			return true
		}
	case reflect.Slice, reflect.Array:
		for i := 0; i < hv.Len(); i++ {
			if objectsEqual(hv.Index(i).Interface(), needle) {
				return true
			}
		}
	case reflect.Map:
		for _, k := range hv.MapKeys() {
			if objectsEqual(k.Interface(), needle) {
				return true
			}
		}
	}
	return a.fail(t, fmt.Sprintf("%#v does not contain %#v", haystack, needle), msgAndArgs)
}

func (a assertions) Empty(t testing.TB, v any, msgAndArgs ...any) bool {
	t.Helper()
	if isEmpty(v) {
		return true
	}
	return a.fail(t, fmt.Sprintf("should be empty: %#v", v), msgAndArgs)
}

func (a assertions) Equal(t testing.TB, want, got any, msgAndArgs ...any) bool {
	t.Helper()
	if objectsEqual(want, got) {
		return true
	}
	return a.fail(t, fmt.Sprintf("not equal:\n  want: %#v\n  got:  %#v", want, got), msgAndArgs)
}

func (a assertions) EqualValues(t testing.TB, want, got any, msgAndArgs ...any) bool {
	t.Helper()
	if objectsEqual(want, got) {
		return true
	}
	wv, gv := reflect.ValueOf(want), reflect.ValueOf(got)
	if wv.IsValid() && gv.IsValid() && wv.Type().ConvertibleTo(gv.Type()) &&
		reflect.DeepEqual(wv.Convert(gv.Type()).Interface(), got) {
		return true
	}
	return a.fail(t, fmt.Sprintf("not equal in value:\n  want: %#v\n  got:  %#v", want, got), msgAndArgs)
}

func (a assertions) Error(t testing.TB, err error, msgAndArgs ...any) bool {
	t.Helper()
	if err != nil {
		return true
	}
	return a.fail(t, "an error is expected", msgAndArgs)
}

func (a assertions) ErrorIs(t testing.TB, err, target error, msgAndArgs ...any) bool {
	t.Helper()
	if errors.Is(err, target) {
		return true
	}
	return a.fail(t, fmt.Sprintf("error %v is not %v", err, target), msgAndArgs)
}

func (a assertions) False(t testing.TB, v bool, msgAndArgs ...any) bool {
	t.Helper()
	if !v {
		return true
	}
	return a.fail(t, "should be false", msgAndArgs)
}

func (a assertions) Len(t testing.TB, v any, n int, msgAndArgs ...any) bool {
	t.Helper()
	if got := reflect.ValueOf(v).Len(); got != n {
		return a.fail(t, fmt.Sprintf("length %d, want %d: %#v", got, n, v), msgAndArgs)
	}
	return true
}

func (a assertions) Less(t testing.TB, x, y any, msgAndArgs ...any) bool {
	t.Helper()
	if c, ok := compare(x, y); ok && c < 0 {
		return true
	}
	return a.fail(t, fmt.Sprintf("%v is not less than %v", x, y), msgAndArgs)
}

func (a assertions) NoError(t testing.TB, err error, msgAndArgs ...any) bool {
	t.Helper()
	if err == nil {
		return true
	}
	return a.fail(t, fmt.Sprintf("unexpected error: %v", err), msgAndArgs)
}

func (a assertions) NotEmpty(t testing.TB, v any, msgAndArgs ...any) bool {
	t.Helper()
	if !isEmpty(v) {
		return true
	}
	return a.fail(t, "should not be empty", msgAndArgs)
}

func (a assertions) Regexp(t testing.TB, rx any, s any, msgAndArgs ...any) bool {
	t.Helper()
	var re *regexp.Regexp
	if r, ok := rx.(*regexp.Regexp); ok {
		re = r
	} else {
		re = regexp.MustCompile(fmt.Sprint(rx))
	}
	if re.MatchString(fmt.Sprint(s)) {
		return true
	}
	return a.fail(t, fmt.Sprintf("%q does not match %q", fmt.Sprint(s), re), msgAndArgs)
}

func (a assertions) True(t testing.TB, v bool, msgAndArgs ...any) bool {
	t.Helper()
	if v {
		return true
	}
	return a.fail(t, "should be true", msgAndArgs)
}

// objectsEqual is reflect.DeepEqual, except that two byte slices compare
// by content and nil-ness.
func objectsEqual(want, got any) bool {
	wb, ok := want.([]byte)
	if !ok {
		return reflect.DeepEqual(want, got)
	}
	gb, ok := got.([]byte)
	return ok && (wb == nil) == (gb == nil) && bytes.Equal(wb, gb)
}

func isEmpty(v any) bool {
	rv := reflect.ValueOf(v)
	if !rv.IsValid() {
		return true
	}
	switch rv.Kind() {
	case reflect.Slice, reflect.Map, reflect.String, reflect.Array, reflect.Chan:
		return rv.Len() == 0
	case reflect.Pointer:
		return rv.IsNil() || isEmpty(rv.Elem().Interface())
	}
	return rv.IsZero()
}

// compare orders two values of the same kind: integers, floats,
// strings and time.Duration. ok is false for anything else or for a
// kind mismatch, which fails the assertion that asked.
func compare(x, y any) (c int, ok bool) {
	xv, yv := reflect.ValueOf(x), reflect.ValueOf(y)
	if !xv.IsValid() || !yv.IsValid() || xv.Type() != yv.Type() {
		return 0, false
	}
	switch xv.Kind() {
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		return cmp.Compare(xv.Int(), yv.Int()), true
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64, reflect.Uintptr:
		return cmp.Compare(xv.Uint(), yv.Uint()), true
	case reflect.Float32, reflect.Float64:
		return cmp.Compare(xv.Float(), yv.Float()), true
	case reflect.String:
		return cmp.Compare(xv.String(), yv.String()), true
	}
	return 0, false
}

// tLogger routes a text logger at the given level into t.Log, so
// output is attributed to its test and stays quiet on a pass.
func tLogger(t testing.TB, level slog.Level) *slog.Logger {
	return slog.New(slog.NewTextHandler(tWriter{t}, &slog.HandlerOptions{Level: level}))
}

type tWriter struct{ t testing.TB }

func (w tWriter) Write(p []byte) (int, error) {
	w.t.Logf("%s %s", time.Now().Format("15:04:05.000"), strings.TrimRight(string(p), "\n"))
	return len(p), nil
}
