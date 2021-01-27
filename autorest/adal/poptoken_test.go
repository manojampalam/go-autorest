package adal

import (
	"bytes"
	"crypto/rsa"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"math/big"
	"testing"

	jwt "github.com/form3tech-oss/jwt-go"
	ms "github.com/mitchellh/mapstructure"
)

func TestAcquirePoPTokenForHost(t *testing.T) {
	tkn := Token{}
	tkn.Type = "pop"
	tkn.poPKey = getSwPoPKey()
	tkn.AccessToken = "abcdefgh"

	popToken, err := tkn.AcquirePoPTokenForHost("my.host.com")
	if err != nil {
		t.Fatal(err)
	}
	//fmt.Println(popToken)
	_, err = jwt.Parse(popToken, func(token *jwt.Token) (interface{}, error) {
		kid := ""
		if len(token.Header) != 3 {
			t.Fatalf("# claims in header: %d, expected: 3", len(token.Header))
		}
		if kid = token.Header["kid"].(string); kid == "" {
			t.Fatalf("no kid in header")
		}
		if alg := token.Header["alg"].(string); alg != "RS256" {
			t.Fatalf("wrong alg in header: %s, expected: RS256", alg)
		}
		if typ := token.Header["typ"].(string); typ != "pop" {
			t.Fatalf("wrong alg in header: %s, expected: pop", typ)
		}

		claims := token.Claims.(jwt.MapClaims)
		if nc := len(claims); nc != 5 {
			t.Fatalf("# claims in body: %d, expected: 5", nc)
		}

		if at := claims["at"].(string); at != "abcdefgh" {
			t.Fatalf("# wrong at: %s, expected: abcdefgh", at)
		}

		if ts := claims["ts"]; ts == nil {
			t.Fatalf("no ts claim")
		}

		if u := claims["u"].(string); u != "my.host.com" {
			t.Fatalf(" wrong u claim: %s, expected: my.host.com", u)
		}

		if nonce := claims["nonce"]; nonce == nil {
			t.Fatalf("no nonce claim")
		}

		var cnf map[string]interface{}
		if cnf = claims["cnf"].(map[string]interface{}); cnf == nil {
			t.Fatalf("no cnf claim")
		}

		//decode public key from cnf claim
		type JWK struct {
			E   string `mapstructure:"e"`
			N   string `mapstructure:"n"`
			Kty string `mapstructure:"kty"`
		}
		var jwk JWK
		err = ms.Decode(cnf["jwk"], &jwk)
		if err != nil {
			t.Fatalf("unable to decode pop public key %v", err)
		}
		if jwk.Kty != "RSA" {
			t.Fatalf("wrong PoP public key type %s", jwk.Kty)
		}

		n, _ := base64.RawURLEncoding.DecodeString(jwk.N)
		e, _ := base64.RawURLEncoding.DecodeString(jwk.E)
		z := new(big.Int)
		z.SetBytes(n)

		var buffer bytes.Buffer
		buffer.WriteByte(0)
		buffer.Write(e)
		exponent := binary.BigEndian.Uint32(buffer.Bytes())
		publicKey := &rsa.PublicKey{N: z, E: int(exponent)}

		return publicKey, nil
	})
	if err != nil {
		t.Fatalf("cannot validate pop token - %v", err)
	}
}

//test pop token
func TestPopTokenE2E(t *testing.T) {
	t.Skip()
	//To test - provide following info

	applicationID := ""
	applicationSecret := ""
	tenantID := ""

	activeDirectoryEndpoint := "https://login.microsoftonline.com/"
	resource := "https://management.core.windows.net/"
	oauthConfig, err := NewOAuthConfig(activeDirectoryEndpoint, tenantID)

	spt, err := NewServicePrincipalToken(
		*oauthConfig,
		applicationID,
		applicationSecret,
		resource)

	if err != nil {
		t.Fatal(err)
	}

	spt.EnablePoP()
	err = spt.Refresh()
	if err != nil {
		t.Fatal(err)
	}

	token := spt.Token()
	popToken, err := token.AcquirePoPTokenForHost("my.host.com")
	if err != nil {
		t.Fatal(err)
	}
	fmt.Println(popToken)
}
