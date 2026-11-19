package jwtutil

import (
	"crypto"
	"maps"
	"reflect"

	"github.com/spiffe/go-spiffe/v2/internal/cryptoutil"
)

// CopyJWTAuthorities copies JWT authorities from a map to a new map.
func CopyJWTAuthorities(jwtAuthorities map[string]crypto.PublicKey) map[string]crypto.PublicKey {
	copiedJWTAuthorities := make(map[string]crypto.PublicKey)
	maps.Copy(copiedJWTAuthorities, jwtAuthorities)
	return copiedJWTAuthorities
}

// PublicKeysEqual reports whether two JWT authority keys hold identical key
// material.
func PublicKeysEqual(a, b crypto.PublicKey) bool {
	equal, err := cryptoutil.PublicKeyEqual(a, b)
	if err != nil {
		return reflect.DeepEqual(a, b)
	}
	return equal
}

func JWTAuthoritiesEqual(a, b map[string]crypto.PublicKey) bool {
	if len(a) != len(b) {
		return false
	}

	for k, pka := range a {
		pkb, ok := b[k]
		if !ok {
			return false
		}
		if equal, _ := cryptoutil.PublicKeyEqual(pka, pkb); !equal {
			return false
		}
	}

	return true
}
