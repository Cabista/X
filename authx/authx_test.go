package authx_test

import (
	"crypto/rand"
	"crypto/rsa"
	"testing"
	"time"

	"github.com/cabista/x/authx"
	"github.com/lestrrat-go/jwx/jwa"
	"github.com/lestrrat-go/jwx/jwk"
	"github.com/lestrrat-go/jwx/jwt"
)

var client authx.AuthClient
var keyID string
var pk *rsa.PrivateKey

func Setup() error {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return err
	}
	jwkKey, err := jwk.New(key)
	if err != nil {
		return err
	}
	jwk.AssignKeyID(jwkKey)
	keyID = jwkKey.KeyID()

	pk = key

	client = authx.AuthClient{
		JwkSet: &jwk.Set{
			Keys: []jwk.Key{jwkKey},
		},
	}
	return nil
}

func TestValidateTokenPass(t *testing.T) {
	err := Setup()
	if err != nil {
		t.Error(err)
	}

	token := jwt.New()
	token.Set(jwt.SubjectKey, "https://github.com/cabista")
	token.Set(jwt.IssuedAtKey, time.Now())
	token.Set(jwt.NotBeforeKey, time.Now())

	//set expiry for 1 day
	token.Set(jwt.ExpirationKey, time.Now().Add(time.Duration(time.Hour*24)))
	token.Set(jwk.KeyIDKey, keyID)

	signedJwt, err := jwt.Sign(token, jwa.RS256, pk)
	if err != nil {
		t.Error(err)
	}

	client.ValidateToken(string(signedJwt), "https://github.com/cabista")

}

func TestValidateTokenInvalidExp(t *testing.T) {
	err := Setup()
	if err != nil {
		t.Error(err)
	}

	token := jwt.New()
	token.Set(jwt.SubjectKey, "https://github.com/cabista")
	token.Set(jwt.IssuedAtKey, time.Now())
	token.Set(jwt.NotBeforeKey, time.Now())

	//set expiry for 1 day
	token.Set(jwt.ExpirationKey, time.Now())
	token.Set(jwk.KeyIDKey, keyID)

	signedJwt, err := jwt.Sign(token, jwa.RS256, pk)
	if err != nil {
		t.Error(err)
	}

	_, err = client.ValidateToken(string(signedJwt), "https://github.com/cabista")
	if err.Error() == "exp not satisfied" {
		return
	}
	if err != nil {
		t.Error(err)
	}
	t.Errorf("Did not throw exp not satisfied")
}

func TestValidateTokenInvalidKid(t *testing.T) {
	err := Setup()
	if err != nil {
		t.Error(err)
	}

	token := jwt.New()
	token.Set(jwt.SubjectKey, "https://github.com/cabista")
	token.Set(jwt.IssuedAtKey, time.Now())
	token.Set(jwt.NotBeforeKey, time.Now())

	//set expiry for 1 day
	token.Set(jwt.ExpirationKey, time.Now())
	token.Set(jwk.KeyIDKey, "invalid")

	signedJwt, err := jwt.Sign(token, jwa.RS256, pk)
	if err != nil {
		t.Error(err)
	}

	_, err = client.ValidateToken(string(signedJwt), "https://github.com/cabista")
	if err.Error() == "Invalid KID" {
		return
	}
	if err != nil {
		t.Error(err)
	}

	t.Errorf("Did not throw Invalid KID")
}

func TestValidateTokenInvalidNBF(t *testing.T) {
	err := Setup()
	if err != nil {
		t.Error(err)
	}

	token := jwt.New()
	token.Set(jwt.SubjectKey, "https://github.com/cabista")
	token.Set(jwt.IssuedAtKey, time.Now())
	token.Set(jwt.NotBeforeKey, time.Now().AddDate(1, 0, 0))

	//set expiry for 1 day
	token.Set(jwt.ExpirationKey, time.Now().Add(time.Duration(time.Hour*24)))
	token.Set(jwk.KeyIDKey, keyID)

	signedJwt, err := jwt.Sign(token, jwa.RS256, pk)
	if err != nil {
		t.Error(err)
	}

	_, err = client.ValidateToken(string(signedJwt), "https://github.com/cabista")
	if err.Error() == "nbf not satisfied" {
		return
	}
	if err != nil {
		t.Error(err)
	}

	t.Errorf("Did not throw nbf not satisfied")
}

func TestValidateTokenInvalidSub(t *testing.T) {
	err := Setup()
	if err != nil {
		t.Error(err)
	}

	token := jwt.New()
	token.Set(jwt.SubjectKey, "https://github.com/cabista/auth")
	token.Set(jwt.IssuedAtKey, time.Now())
	token.Set(jwt.NotBeforeKey, time.Now())

	//set expiry for 1 day
	token.Set(jwt.ExpirationKey, time.Now().Add(time.Duration(time.Hour*24)))
	token.Set(jwk.KeyIDKey, keyID)

	signedJwt, err := jwt.Sign(token, jwa.RS256, pk)
	if err != nil {
		t.Error(err)
	}

	_, err = client.ValidateToken(string(signedJwt), "https://github.com/cabista")
	if err.Error() == "sub not satisfied" {
		return
	}
	if err != nil {
		t.Error(err)
	}

	t.Errorf("Did not throw sub not satisfied")
}

func TestValidateTokenInvalidFormat(t *testing.T) {
	err := Setup()
	if err != nil {
		t.Error(err)
	}

	_, err = client.ValidateToken("dwiiwn", "")
	if err == nil {
		t.Errorf("token should of thrown a error")
	}
}
