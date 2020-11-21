package authx

import (
	"fmt"
	"net/http"

	"github.com/labstack/echo"
	"github.com/lestrrat-go/jwx/jwk"
	"github.com/lestrrat-go/jwx/jws"
	"github.com/lestrrat-go/jwx/jwt"
)

type AuthClient struct {
	JwkSet  *jwk.Set
	Subject string
}

func NewAuthClient(url string, subject string) (*AuthClient, error) {
	set, err := jwk.Fetch(url)
	if err != nil {
		return nil, err
	}

	return &AuthClient{
		JwkSet: set,
	}, nil
}

func (a *AuthClient) ValidateRequestMiddleware(next echo.HandlerFunc) echo.HandlerFunc {
	return func(c echo.Context) error {
		header := c.Request().Header.Get("Authorization")
		token, err := a.ValidateToken(header, a.Subject)
		if err != nil {
			fmt.Println(err)
			return c.JSON(http.StatusUnauthorized, nil)
		}
		c.Set("jwt", token)
		return next(c)
	}
}

func (a *AuthClient) ValidateToken(token string, subject string) (jwt.Token, error) {
	tok, err := jwt.ParseString(token)
	if err != nil {
		return nil, err
	}

	key, found := tok.Get(jwk.KeyIDKey)
	if !found {
		return nil, fmt.Errorf("This JWT does not contain a kid")
	}

	kids := a.JwkSet.LookupKeyID(key.(string))

	var kidErr error

	for _, kid := range kids {
		_, kidErr = jws.VerifyWithJWK([]byte(token), kid)
	}

	if kidErr == nil {
		return nil, fmt.Errorf("Invalid KID")
	}

	err = jwt.Verify(tok, jwt.WithSubject(subject))

	if err != nil {
		return nil, err
	}

	// if tok.NotBefore().Before(time.Now()) {
	// 	return nil, fmt.Errorf("nbf not satisfied")
	// }

	return tok, nil
}
