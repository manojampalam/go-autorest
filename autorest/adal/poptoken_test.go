package adal

import (
	"errors"
	"fmt"
	"testing"

	jwt "github.com/form3tech-oss/jwt-go"
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
	fmt.Println(popToken)
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

		if cnf := claims["cnf"]; cnf == nil {
			t.Fatalf("no cnf claim")
		}

		//TODO parse, hydrate public key and return
		return nil, errors.New("not supported yet")
	})
	if err != nil {
		fmt.Println("cannot parse token - ", err)
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

	jwtToken, err := jwt.Parse(popToken, func(token *jwt.Token) (interface{}, error) {
		kidInt := token.Header["kid"]
		if kidInt == nil {
			return nil, errors.New("no kid found in header")
		}
		kid, ok := kidInt.(string)
		if ok == false {
			return nil, errors.New("kid is not a string")
		}
		fmt.Println(kid)
		return nil, errors.New("not supported yet")
	})
	if err != nil {
		fmt.Println("cannot parse token - ", err)
	}

	claims := jwtToken.Claims.(jwt.MapClaims)
	if claims["iat"] == nil || claims["tid"] == nil {
		fmt.Println("token did not have tid or iat fields")
	}
}
