package adal

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"math/big"
)

// Copyright 2017 Microsoft Corporation
//
//  Licensed under the Apache License, Version 2.0 (the "License");
//  you may not use this file except in compliance with the License.
//  You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
//  Unless required by applicable law or agreed to in writing, software
//  distributed under the License is distributed on an "AS IS" BASIS,
//  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
//  See the License for the specific language governing permissions and
//  limitations under the License.

type PoPKey interface {
	KeyID() string
	JWK() string
	JWKThumbprint() string
	Sign([]byte) ([]byte, error)
}

type swKey struct {
	key   *rsa.PrivateKey
	keyID string
	jwk   string
	jwktp string
}

func (swk *swKey) KeyID() string {
	return swk.keyID
}

func (swk *swKey) JWK() string {
	return swk.jwk
}

func (swk *swKey) JWKThumbprint() string {
	return swk.jwktp
}

func (swk *swKey) Sign([]byte) ([]byte, error) {
	return nil, errors.New("not implemented")
}

func generateSwKey() (*swKey, error) {
	var err error
	swk := &swKey{}
	swk.key, err = rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}

	pubKey := &swk.key.PublicKey
	e := big.NewInt(int64(pubKey.E))
	eB64 := base64.RawURLEncoding.EncodeToString(e.Bytes())
	n := pubKey.N
	nB64 := base64.RawURLEncoding.EncodeToString(n.Bytes())
	swk.jwk = fmt.Sprintf(`{"e":"%s","kty":"RSA","n":"%s"}`, eB64, nB64)

	jwkS256 := sha256.Sum256([]byte(swk.jwk))
	swk.jwktp = base64.RawURLEncoding.EncodeToString(jwkS256[:])

	return swk, nil
}
