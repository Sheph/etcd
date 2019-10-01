// Copyright 2017 The etcd Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package auth

import (
	"context"
	"crypto/rsa"
	"io/ioutil"

	jwt "github.com/dgrijalva/jwt-go"
)

type tokenJWT struct {
	signMethod string
	signKey    *rsa.PrivateKey
	verifyKey  *rsa.PublicKey
	hmacKey    []byte
}

func (t *tokenJWT) enable()                         {}
func (t *tokenJWT) disable()                        {}
func (t *tokenJWT) invalidateUser(string)           {}
func (t *tokenJWT) genTokenPrefix() (string, error) { return "", nil }

func (t *tokenJWT) info(ctx context.Context, token string) (*AuthInfo, bool) {
	// rev isn't used in JWT, it is only used in simple token
	var (
		username string
		revision uint64
	)

	parsed, err := jwt.Parse(token, func(token *jwt.Token) (interface{}, error) {
		if t.hmacKey != nil {
			return t.hmacKey, nil
		}
		return t.verifyKey, nil
	})

	switch err.(type) {
	case nil:
		if !parsed.Valid {
			plog.Warningf("invalid jwt token: %s", token)
			return nil, false
		}

		claims := parsed.Claims.(jwt.MapClaims)

		username = claims["username"].(string)
		revision = uint64(claims["revision"].(float64))
		if revision == 0 {
			plog.Warningf("invalid jwt token: %s", token)
			return nil, false
		}
	default:
		plog.Warningf("failed to parse jwt token: %s", err)
		return nil, false
	}

	return &AuthInfo{Username: username, Revision: revision}, true
}

func (t *tokenJWT) assign(ctx context.Context, username string, revision uint64) (string, error) {
	// Future work: let a jwt token include permission information would be useful for
	// permission checking in proxy side.
	tk := jwt.NewWithClaims(jwt.GetSigningMethod(t.signMethod),
		jwt.MapClaims{
			"username": username,
			"revision": revision,
		})

	var token string
	var err error
	if t.hmacKey != nil {
		token, err = tk.SignedString(t.hmacKey)
	} else {
		token, err = tk.SignedString(t.signKey)
	}
	if err != nil {
		plog.Debugf("failed to sign jwt token: %s", err)
		return "", err
	}

	plog.Debugf("jwt token: %s", token)

	return token, err
}

func prepareOpts(opts map[string]string) (jwtSignMethod, jwtPubKeyPath, jwtPrivKeyPath, jwtHMACKeyPath string, err error) {
	for k, v := range opts {
		switch k {
		case "sign-method":
			jwtSignMethod = v
		case "pub-key":
			jwtPubKeyPath = v
		case "priv-key":
			jwtPrivKeyPath = v
		case "hmac-key":
			jwtHMACKeyPath = v
		default:
			plog.Errorf("unknown token specific option: %s", k)
			return "", "", "", "", ErrInvalidAuthOpts
		}
	}
	if len(jwtSignMethod) == 0 {
		return "", "", "", "", ErrInvalidAuthOpts
	}
	return jwtSignMethod, jwtPubKeyPath, jwtPrivKeyPath, jwtHMACKeyPath, nil
}

func newTokenProviderJWT(opts map[string]string) (*tokenJWT, error) {
	jwtSignMethod, jwtPubKeyPath, jwtPrivKeyPath, jwtHMACKeyPath, err := prepareOpts(opts)
	if err != nil {
		return nil, ErrInvalidAuthOpts
	}

	t := &tokenJWT{}

	t.signMethod = jwtSignMethod

	if jwtHMACKeyPath != "" {
		hmacKey, err := ioutil.ReadFile(jwtHMACKeyPath)
		if err != nil {
			plog.Errorf("failed to read HMAC key (%s) for jwt: %s", jwtHMACKeyPath, err)
			return nil, err
		}
		if len(hmacKey) <= 0 {
			plog.Errorf("bad HMAC key (%s) for jwt", jwtHMACKeyPath)
			return nil, ErrInvalidAuthOpts
		}
		t.hmacKey = hmacKey
		return t, nil
	}

	verifyBytes, err := ioutil.ReadFile(jwtPubKeyPath)
	if err != nil {
		plog.Errorf("failed to read public key (%s) for jwt: %s", jwtPubKeyPath, err)
		return nil, err
	}
	t.verifyKey, err = jwt.ParseRSAPublicKeyFromPEM(verifyBytes)
	if err != nil {
		plog.Errorf("failed to parse public key (%s): %s", jwtPubKeyPath, err)
		return nil, err
	}

	signBytes, err := ioutil.ReadFile(jwtPrivKeyPath)
	if err != nil {
		plog.Errorf("failed to read private key (%s) for jwt: %s", jwtPrivKeyPath, err)
		return nil, err
	}
	t.signKey, err = jwt.ParseRSAPrivateKeyFromPEM(signBytes)
	if err != nil {
		plog.Errorf("failed to parse private key (%s): %s", jwtPrivKeyPath, err)
		return nil, err
	}

	return t, nil
}
