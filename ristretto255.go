// Copyright 2019 The Go Authors. All rights reserved.
// Copyright 2019 George Tankersley. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package ristretto255 implements the group of prime order
//
//     2**252 + 27742317777372353535851937790883648493
//
// as specified in draft-hdevalence-cfrg-ristretto-01.
//
// All operations are constant time unless otherwise specified.
package ristretto255

import (
	"bytes"
	"encoding/base64"
	"errors"

	"filippo.io/edwards25519"
	"filippo.io/edwards25519/field"
)

// Constants from draft-hdevalence-cfrg-ristretto-01, Section 3.1. See
// TestConstants for their decimal values.
var (
	d, _ = new(field.Element).SetBytes([]byte{
		0xa3, 0x78, 0x59, 0x13, 0xca, 0x4d, 0xeb, 0x75,
		0xab, 0xd8, 0x41, 0x41, 0x4d, 0x0a, 0x70, 0x00,
		0x98, 0xe8, 0x79, 0x77, 0x79, 0x40, 0xc7, 0x8c,
		0x73, 0xfe, 0x6f, 0x2b, 0xee, 0x6c, 0x03, 0x52,
	})
	sqrtM1, _ = new(field.Element).SetBytes([]byte{
		0xb0, 0xa0, 0x0e, 0x4a, 0x27, 0x1b, 0xee, 0xc4,
		0x78, 0xe4, 0x2f, 0xad, 0x06, 0x18, 0x43, 0x2f,
		0xa7, 0xd7, 0xfb, 0x3d, 0x99, 0x00, 0x4d, 0x2b,
		0x0b, 0xdf, 0xc1, 0x4f, 0x80, 0x24, 0x83, 0x2b,
	})
	sqrtADMinusOne, _ = new(field.Element).SetBytes([]byte{
		0x1b, 0x2e, 0x7b, 0x49, 0xa0, 0xf6, 0x97, 0x7e,
		0xbd, 0x54, 0x78, 0x1b, 0x0c, 0x8e, 0x9d, 0xaf,
		0xfd, 0xd1, 0xf5, 0x31, 0xc9, 0xfc, 0x3c, 0x0f,
		0xac, 0x48, 0x83, 0x2b, 0xbf, 0x31, 0x69, 0x37,
	})
	invSqrtAMinusD, _ = new(field.Element).SetBytes([]byte{
		0xea, 0x40, 0x5d, 0x80, 0xaa, 0xfd, 0xc8, 0x99,
		0xbe, 0x72, 0x41, 0x5a, 0x17, 0x16, 0x2f, 0x9d,
		0x40, 0xd8, 0x01, 0xfe, 0x91, 0x7b, 0xc2, 0x16,
		0xa2, 0xfc, 0xaf, 0xcf, 0x05, 0x89, 0x6c, 0x78,
	})
	oneMinusDSQ, _ = new(field.Element).SetBytes([]byte{
		0x76, 0xc1, 0x5f, 0x94, 0xc1, 0x09, 0x7c, 0xe2,
		0x0f, 0x35, 0x5e, 0xcd, 0x38, 0xa1, 0x81, 0x2c,
		0xe4, 0xdf, 0x70, 0xbe, 0xdd, 0xab, 0x94, 0x99,
		0xd7, 0xe0, 0xb3, 0xb2, 0xa8, 0x72, 0x90, 0x02,
	})
	dMinusOneSQ, _ = new(field.Element).SetBytes([]byte{
		0x20, 0x4d, 0xed, 0x44, 0xaa, 0x5a, 0xad, 0x31,
		0x99, 0x19, 0x1e, 0xb0, 0x2c, 0x4a, 0x9e, 0xd2,
		0xeb, 0x4e, 0x9b, 0x52, 0x2f, 0xd3, 0xdc, 0x4c,
		0x41, 0x22, 0x6c, 0xf6, 0x7a, 0xb3, 0x68, 0x59,
	})
)

var (
	zero     = new(field.Element)
	one      = new(field.Element).One()
	two      = new(field.Element).Add(one, one)
	minusOne = new(field.Element).Subtract(zero, one)
)

// Element is an element of the ristretto255 prime-order group.
type Element struct {
	r edwards25519.Point
}

// NewElement returns a new Element set to the identity value.
//
// Deprecated: use NewIdentityElement. This API will be removed before v1.0.0.
func NewElement() *Element {
	return NewIdentityElement()
}

// NewIdentityElement returns a new Element set to the identity value.
func NewIdentityElement() *Element {
	e := &Element{}
	e.r.Set(edwards25519.NewIdentityPoint())
	return e
}

// NewGeneratorElement returns a new Element set to the canonical generator.
func NewGeneratorElement() *Element {
	e := &Element{}
	e.r.Set(edwards25519.NewGeneratorPoint())
	return e
}

// Set sets the value of e to x and returns e.
func (e *Element) Set(x *Element) *Element {
	*e = *x
	return e
}

// Equal returns 1 if e is equivalent to ee, and 0 otherwise.
//
// Note that Elements must not be compared in any other way.
func (e *Element) Equal(ee *Element) int {
	X1, Y1, _, _ := e.r.ExtendedCoordinates()
	X2, Y2, _, _ := ee.r.ExtendedCoordinates()

	var f0, f1 field.Element

	f0.Multiply(X1, Y2) // x1 * y2
	f1.Multiply(Y1, X2) // y1 * x2
	out := f0.Equal(&f1)

	f0.Multiply(Y1, Y2) // y1 * y2
	f1.Multiply(X1, X2) // x1 * x2
	out = out | f0.Equal(&f1)

	return out
}

// FromUniformBytes maps the 64-byte slice b to e uniformly and
// deterministically, and returns e. This can be used for hash-to-group
// operations or to obtain a random element.
//
// Deprecated: use SetUniformBytes. This API will be removed before v1.0.0.
func (e *Element) FromUniformBytes(b []byte) *Element {
	if _, err := e.SetUniformBytes(b); err != nil {
		panic(err.Error())
	}
	return e
}

// SetUniformBytes deterministically sets e to an uniformly distributed value
// given 64 uniformly distributed random bytes.
//
// This can be used for hash-to-group operations or to obtain a random element.
func (e *Element) SetUniformBytes(b []byte) (*Element, error) {
	if len(b) != 64 {
		return nil, errors.New("ristretto255: SetUniformBytes input is not 64 bytes long")
	}

	f := &field.Element{}

	f.SetBytes(b[:32])
	point1 := &Element{}
	mapToPoint(&point1.r, f)

	f.SetBytes(b[32:])
	point2 := &Element{}
	mapToPoint(&point2.r, f)

	return e.Add(point1, point2), nil
}

// mapToPoint implements MAP from Section 3.2.4 of draft-hdevalence-cfrg-ristretto-00.
func mapToPoint(out *edwards25519.Point, t *field.Element) {
	// r = SQRT_M1 * t^2
	r := &field.Element{}
	r.Multiply(sqrtM1, r.Square(t))

	// u = (r + 1) * ONE_MINUS_D_SQ
	u := &field.Element{}
	u.Multiply(u.Add(r, one), oneMinusDSQ)

	// c = -1
	c := &field.Element{}
	c.Set(minusOne)

	// v = (c - r*D) * (r + D)
	rPlusD := &field.Element{}
	rPlusD.Add(r, d)
	v := &field.Element{}
	v.Multiply(v.Subtract(c, v.Multiply(r, d)), rPlusD)

	// (was_square, s) = SQRT_RATIO_M1(u, v)
	s := &field.Element{}
	_, wasSquare := s.SqrtRatio(u, v)

	// s_prime = -CT_ABS(s*t)
	sPrime := &field.Element{}
	sPrime.Negate(sPrime.Absolute(sPrime.Multiply(s, t)))

	// s = CT_SELECT(s IF was_square ELSE s_prime)
	s.Select(s, sPrime, wasSquare)
	// c = CT_SELECT(c IF was_square ELSE r)
	c.Select(c, r, wasSquare)

	// N = c * (r - 1) * D_MINUS_ONE_SQ - v
	N := &field.Element{}
	N.Multiply(c, N.Subtract(r, one))
	N.Subtract(N.Multiply(N, dMinusOneSQ), v)

	s2 := &field.Element{}
	s2.Square(s)

	// w0 = 2 * s * v
	w0 := &field.Element{}
	w0.Add(w0, w0.Multiply(s, v))
	// w1 = N * SQRT_AD_MINUS_ONE
	w1 := &field.Element{}
	w1.Multiply(N, sqrtADMinusOne)
	// w2 = 1 - s^2
	w2 := &field.Element{}
	w2.Subtract(one, s2)
	// w3 = 1 + s^2
	w3 := &field.Element{}
	w3.Add(one, s2)

	// return (w0*w3, w2*w1, w1*w3, w0*w2)
	var X, Y, Z, T field.Element
	X.Multiply(w0, w3)
	Y.Multiply(w2, w1)
	Z.Multiply(w1, w3)
	T.Multiply(w0, w2)
	if _, err := out.SetExtendedCoordinates(&X, &Y, &Z, &T); err != nil {
		panic("ristretto255: internal error: MAP generated invalid coordinates")
	}
}

// Encode appends the 32 bytes canonical encoding of e to b
// and returns the result.
//
// Deprecated: use Bytes. This API will be removed before v1.0.0.
func (e *Element) Encode(b []byte) []byte {
	ret, out := sliceForAppend(b, 32)
	e.bytes(out)
	return ret
}

// sliceForAppend takes a slice and a requested number of bytes. It returns a
// slice with the contents of the given slice followed by that many bytes and a
// second slice that aliases into it and contains only the extra bytes. If the
// original slice has sufficient capacity then no allocation is performed.
func sliceForAppend(in []byte, n int) (head, tail []byte) {
	if total := len(in) + n; cap(in) >= total {
		head = in[:total]
	} else {
		head = make([]byte, total)
		copy(head, in)
	}
	tail = head[len(in):]
	return
}

// Bytes returns the 32 bytes canonical encoding of e.
func (e *Element) Bytes() []byte {
	// Bytes is outlined to let the allocation happen on the stack of the caller.
	b := make([]byte, 32)
	return e.bytes(b)
}

func (e *Element) bytes(b []byte) []byte {
	X, Y, Z, T := e.r.ExtendedCoordinates()
	tmp := &field.Element{}

	// u1 = (z0 + y0) * (z0 - y0)
	u1 := &field.Element{}
	u1.Add(Z, Y).Multiply(u1, tmp.Subtract(Z, Y))

	// u2 = x0 * y0
	u2 := &field.Element{}
	u2.Multiply(X, Y)

	// Ignore was_square since this is always square
	// (_, invsqrt) = SQRT_RATIO_M1(1, u1 * u2^2)
	invSqrt := &field.Element{}
	invSqrt.SqrtRatio(one, tmp.Square(u2).Multiply(tmp, u1))

	// den1 = invsqrt * u1
	// den2 = invsqrt * u2
	den1, den2 := &field.Element{}, &field.Element{}
	den1.Multiply(invSqrt, u1)
	den2.Multiply(invSqrt, u2)
	// z_inv = den1 * den2 * t0
	zInv := &field.Element{}
	zInv.Multiply(den1, den2).Multiply(zInv, T)

	// ix0 = x0 * SQRT_M1
	// iy0 = y0 * SQRT_M1
	ix0, iy0 := &field.Element{}, &field.Element{}
	ix0.Multiply(X, sqrtM1)
	iy0.Multiply(Y, sqrtM1)
	// enchanted_denominator = den1 * INVSQRT_A_MINUS_D
	enchantedDenominator := &field.Element{}
	enchantedDenominator.Multiply(den1, invSqrtAMinusD)

	// rotate = IS_NEGATIVE(t0 * z_inv)
	rotate := tmp.Multiply(T, zInv).IsNegative()

	// x = CT_SELECT(iy0 IF rotate ELSE x0)
	// y = CT_SELECT(ix0 IF rotate ELSE y0)
	x, y := &field.Element{}, &field.Element{}
	x.Select(iy0, X, rotate)
	y.Select(ix0, Y, rotate)
	// z = z0
	z := Z
	// den_inv = CT_SELECT(enchanted_denominator IF rotate ELSE den2)
	denInv := &field.Element{}
	denInv.Select(enchantedDenominator, den2, rotate)

	// y = CT_NEG(y, IS_NEGATIVE(x * z_inv))
	isNegative := tmp.Multiply(x, zInv).IsNegative()
	y.Select(tmp.Negate(y), y, isNegative)

	// s = CT_ABS(den_inv * (z - y))
	s := tmp.Subtract(z, y).Multiply(tmp, denInv).Absolute(tmp)

	// Return the canonical little-endian encoding of s.
	copy(b, s.Bytes())
	return b
}

var errInvalidEncoding = errors.New("ristretto255: invalid element encoding")

// Decode sets e to the decoded value of in. If in is not a 32 byte canonical
// encoding, Decode returns an error, and the receiver is unchanged.
//
// Deprecated: use SetCanonicalBytes. This API will be removed before v1.0.0.
func (e *Element) Decode(in []byte) error {
	_, err := e.SetCanonicalBytes(in)
	return err
}

// SetCanonicalBytes sets e to the decoded value of in. If in is not a canonical
// encoding of s, SetCanonicalBytes returns nil and an error and the receiver is
// unchanged.
func (e *Element) SetCanonicalBytes(in []byte) (*Element, error) {
	if len(in) != 32 {
		return nil, errInvalidEncoding
	}

	// First, interpret the string as an integer s in little-endian representation.
	s := &field.Element{}
	s.SetBytes(in)

	// If the resulting value is >= p, decoding fails.
	if !bytes.Equal(s.Bytes(), in) {
		return nil, errInvalidEncoding
	}

	// If IS_NEGATIVE(s) returns TRUE, decoding fails.
	if s.IsNegative() == 1 {
		return nil, errInvalidEncoding
	}

	// ss = s^2
	sSqr := &field.Element{}
	sSqr.Square(s)

	// u1 = 1 - ss
	u1 := &field.Element{}
	u1.Subtract(one, sSqr)

	// u2 = 1 + ss
	u2 := &field.Element{}
	u2.Add(one, sSqr)

	// u2_sqr = u2^2
	u2Sqr := &field.Element{}
	u2Sqr.Square(u2)

	// v = -(D * u1^2) - u2_sqr
	v := &field.Element{}
	v.Square(u1).Multiply(v, d).Negate(v).Subtract(v, u2Sqr)

	// (was_square, invsqrt) = SQRT_RATIO_M1(1, v * u2_sqr)
	invSqrt, tmp := &field.Element{}, &field.Element{}
	_, wasSquare := invSqrt.SqrtRatio(one, tmp.Multiply(v, u2Sqr))

	// den_x = invsqrt * u2
	// den_y = invsqrt * den_x * v
	denX, denY := &field.Element{}, &field.Element{}
	denX.Multiply(invSqrt, u2)
	denY.Multiply(invSqrt, denX).Multiply(denY, v)

	// x = CT_ABS(2 * s * den_x)
	// y = u1 * den_y
	// t = x * y
	var X, Y, Z, T field.Element
	X.Multiply(two, s).Multiply(&X, denX).Absolute(&X)
	Y.Multiply(u1, denY)
	Z.One()
	T.Multiply(&X, &Y)

	// If was_square is FALSE, or IS_NEGATIVE(t) returns TRUE, or y = 0, decoding fails.
	if wasSquare == 0 || T.IsNegative() == 1 || Y.Equal(zero) == 1 {
		return nil, errInvalidEncoding
	}

	// Otherwise, return the internal representation in extended coordinates (x, y, 1, t).
	if _, err := e.r.SetExtendedCoordinates(&X, &Y, &Z, &T); err != nil {
		panic("ristretto255: internal error: DECODE generated invalid coordinates")
	}
	return e, nil
}

// ScalarBaseMult sets e = s * B, where B is the canonical generator, and returns e.
func (e *Element) ScalarBaseMult(s *Scalar) *Element {
	e.r.ScalarBaseMult(&s.s)
	return e
}

// ScalarMult sets e = s * p, and returns e.
func (e *Element) ScalarMult(s *Scalar, p *Element) *Element {
	e.r.ScalarMult(&s.s, &p.r)
	return e
}

// MultiScalarMult sets e = sum(s[i] * p[i]), and returns e.
//
// Execution time depends only on the lengths of the two slices, which must match.
func (e *Element) MultiScalarMult(s []*Scalar, p []*Element) *Element {
	if len(p) != len(s) {
		panic("ristretto255: MultiScalarMult invoked with mismatched slice lengths")
	}
	points := make([]*edwards25519.Point, len(p))
	scalars := make([]*edwards25519.Scalar, len(s))
	for i := range s {
		points[i] = &p[i].r
		scalars[i] = &s[i].s
	}
	e.r.MultiScalarMult(scalars, points)
	return e
}

// VarTimeMultiScalarMult sets e = sum(s[i] * p[i]), and returns e.
//
// Execution time depends on the inputs.
func (e *Element) VarTimeMultiScalarMult(s []*Scalar, p []*Element) *Element {
	if len(p) != len(s) {
		panic("ristretto255: VarTimeMultiScalarMult invoked with mismatched slice lengths")
	}
	points := make([]*edwards25519.Point, len(p))
	scalars := make([]*edwards25519.Scalar, len(s))
	for i := range s {
		points[i] = &p[i].r
		scalars[i] = &s[i].s
	}
	e.r.VarTimeMultiScalarMult(scalars, points)
	return e
}

// VarTimeDoubleScalarBaseMult sets e = a * A + b * B, where B is the canonical
// generator, and returns e.
//
// Execution time depends on the inputs.
func (e *Element) VarTimeDoubleScalarBaseMult(a *Scalar, A *Element, b *Scalar) *Element {
	e.r.VarTimeDoubleScalarBaseMult(&a.s, &A.r, &b.s)
	return e
}

// Add sets e = p + q, and returns e.
func (e *Element) Add(p, q *Element) *Element {
	e.r.Add(&p.r, &q.r)
	return e
}

// Subtract sets e = p - q, and returns e.
func (e *Element) Subtract(p, q *Element) *Element {
	e.r.Subtract(&p.r, &q.r)
	return e
}

// Negate sets e = -p, and returns e.
func (e *Element) Negate(p *Element) *Element {
	e.r.Negate(&p.r)
	return e
}

// Zero sets e to the identity element of the group, and returns e.
//
// Deprecated: use NewIdentityElement and Set. This API will be removed before v1.0.0.
func (e *Element) Zero() *Element {
	return e.Set(NewIdentityElement())
}

// Base sets e to the canonical generator specified in
// draft-hdevalence-cfrg-ristretto-01, Section 3, and returns e.
//
// Deprecated: use NewGeneratorElement and Set. This API will be removed before v1.0.0.
func (e *Element) Base() *Element {
	return e.Set(NewGeneratorElement())
}

// MarshalText implements encoding/TextMarshaler interface
func (e *Element) MarshalText() (text []byte, err error) {
	b := e.Encode([]byte{})
	return []byte(base64.StdEncoding.EncodeToString(b)), nil
}

// UnmarshalText implements encoding/TextMarshaler interface
func (e *Element) UnmarshalText(text []byte) error {
	eb, err := base64.StdEncoding.DecodeString(string(text))
	if err == nil {
		return e.Decode(eb)
	}
	return err
}

// String implements the Stringer interface
func (e *Element) String() string {
	result, _ := e.MarshalText()
	return string(result)
}
