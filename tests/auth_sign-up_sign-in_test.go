package tests

import (
	"testing"
	"time"

	ssov1 "github.com/DavidG9999/api/gen/go/sso"
	"github.com/DavidG9999/my_grpc_app/tests/suite"
	"github.com/brianvoe/gofakeit/v6"
	"github.com/dgrijalva/jwt-go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	emptyAppID = 0
	appID      = 1
	appSecret  = "test-secret"

	passDefaultLen = 10
)

func TestSignUp_SignIn_HappyPath(t *testing.T) {
	ctx, st := suite.NewSuite(t)

	name := gofakeit.Username()
	email := gofakeit.Email()
	password := randomFakePassword()
	isAdmin := gofakeit.Bool()

	respSignUp, err := st.AuthClient.SignUp(ctx, &ssov1.SignUpRequest{
		Name:     name,
		Email:    email,
		Password: password,
		IsAdmin:  isAdmin,
	})
	require.NoError(t, err)
	assert.NotEmpty(t, respSignUp.GetUserId())

	respSignIn, err := st.AuthClient.SignIn(ctx, &ssov1.SignInRequest{
		Email:    email,
		Password: password,
		AppId:    appID,
	})

	require.NoError(t, err)

	loginTime := time.Now()

	token := respSignIn.GetToken()
	require.NotEmpty(t, token)

	tokenParsed, err := jwt.Parse(token, func(token *jwt.Token) (interface{}, error) {
		return []byte(appSecret), nil
	})
	require.NoError(t, err)

	claims, ok := tokenParsed.Claims.(jwt.MapClaims)
	require.True(t, ok)

	assert.Equal(t, respSignUp.GetUserId(), int64(claims["uid"].(float64)))
	assert.Equal(t, email, claims["email"].(string))
	assert.Equal(t, appID, int(claims["app_id"].(float64)))

	const deltaSeconds = 1
	assert.InDelta(t, loginTime.Add(st.Cfg.TokenTTL).Unix(), claims["exp"].(float64), deltaSeconds)
}

func randomFakePassword() string {
	return gofakeit.Password(true, true, true, true, true, passDefaultLen)
}
