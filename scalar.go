// Copyright 2019 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package ristretto255

import (
	"encoding/base64"
	"errors"

	"filippo.io/edwards25519"
)

// A Scalar is an element of the ristretto255 scalar field, as specified in
// draft-hdevalence-cfrg-ristretto-01, Section 3.4. That is, an integer modulo
//
//     l = 2^252 + 27742317777372353535851937790883648493
//
// The zero value is a valid zero element.
type Scalar struct {
	s edwards25519.Scalar
}

// NewScalar returns a Scalar set to the value 0.
func NewScalar() *Scalar {
	return &Scalar{}
}

// Set sets the value of s to x and returns s.
func (s *Scalar) Set(x *Scalar) *Scalar {
	*s = *x
	return s
}

// Add sets s = x + y mod l and returns s.
func (s *Scalar) Add(x, y *Scalar) *Scalar {
	s.s.Add(&x.s, &y.s)
	return s
}

// Subtract sets s = x - y mod l and returns s.
func (s *Scalar) Subtract(x, y *Scalar) *Scalar {
	s.s.Subtract(&x.s, &y.s)
	return s
}

// Negate sets s = -x mod l and returns s.
func (s *Scalar) Negate(x *Scalar) *Scalar {
	s.s.Negate(&x.s)
	return s
}

// Multiply sets s = x * y mod l and returns s.
func (s *Scalar) Multiply(x, y *Scalar) *Scalar {
	s.s.Multiply(&x.s, &y.s)
	return s
}

// Invert sets s = 1 / x such that s * x = 1 mod l and returns s.
//
// If x is 0, the result is undefined.
func (s *Scalar) Invert(x *Scalar) *Scalar {
	s.s.Invert(&x.s)
	return s
}

// FromUniformBytes sets s to an uniformly distributed value given 64 uniformly
// distributed random bytes.
//
// Deprecated: use SetUniformBytes. This API will be removed before v1.0.0.
func (s *Scalar) FromUniformBytes(x []byte) *Scalar {
	if _, err := s.SetUniformBytes(x); err != nil {
		panic(err.Error())
	}
	return s
}

// SetUniformBytes sets s to an uniformly distributed value given 64 uniformly
// distributed random bytes. If x is not of the right length, SetUniformBytes
// returns nil and an error, and the receiver is unchanged.
func (s *Scalar) SetUniformBytes(x []byte) (*Scalar, error) {
	if _, err := s.s.SetUniformBytes(x); err != nil {
		return nil, errors.New("ristretto255: SetUniformBytes input is not 64 bytes long")
	}
	return s, nil
}

// Decode sets s = x, where x is a 32 bytes little-endian encoding of s. If x is
// not a canonical encoding of s, Decode returns an error and the receiver is
// unchanged.
//
// Deprecated: use SetCanonicalBytes. This API will be removed before v1.0.0.
func (s *Scalar) Decode(x []byte) error {
	_, err := s.SetCanonicalBytes(x)
	return err
}

// SetCanonicalBytes sets s = x, where x is a 32 bytes little-endian encoding of
// s. If x is not a canonical encoding of s, SetCanonicalBytes returns nil and
// an error and the receiver is unchanged.
func (s *Scalar) SetCanonicalBytes(x []byte) (*Scalar, error) {
	if _, err := s.s.SetCanonicalBytes(x); err != nil {
		return nil, errors.New("ristretto255: " + err.Error())
	}
	return s, nil
}

// Encode appends a 32 bytes little-endian encoding of s to b.
//
// Deprecated: use Bytes. This API will be removed before v1.0.0.
func (s *Scalar) Encode(b []byte) []byte {
	ret, out := sliceForAppend(b, 32)
	copy(out, s.s.Bytes())
	return ret
}

// Bytes returns the 32 bytes little-endian encoding of s.
func (s *Scalar) Bytes() []byte {
	return s.s.Bytes()
}

// Equal returns 1 if v and u are equal, and 0 otherwise.
func (s *Scalar) Equal(u *Scalar) int {
	return s.s.Equal(&u.s)
}

// Zero sets s = 0 and returns s.
func (s *Scalar) Zero() *Scalar {
	s.s = edwards25519.Scalar{}
	return s
}

// MarshalText implements encoding/TextMarshaler interface
func (s *Scalar) MarshalText() (text []byte, err error) {
	b := s.Encode([]byte{})
	return []byte(base64.StdEncoding.EncodeToString(b)), nil
}

// UnmarshalText implements encoding/TextMarshaler interface
func (s *Scalar) UnmarshalText(text []byte) error {
	sb, err := base64.StdEncoding.DecodeString(string(text))
	if err == nil {
		return s.Decode(sb)
	}
	return err
}

// String implements the Stringer interface
func (s *Scalar) String() string {
	result, _ := s.MarshalText()
	return string(result)
}
