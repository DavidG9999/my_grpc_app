package tests

import (
	"fmt"
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

func Test_SignUp_SignIn_IsAdmin_HappyPath(t *testing.T) {
	ctx, st := suite.NewSuite(t)

	tests := []struct {
		name     string
		email    string
		password string
		isAdmin  bool
	}{
		{
			name:     gofakeit.Username(),
			email:    gofakeit.Email(),
			password: randomFakePassword(),
			isAdmin:  gofakeit.Bool(),
		},
		{
			name:     gofakeit.Username(),
			email:    gofakeit.Email(),
			password: randomFakePassword(),
		},
	}
	i := 1
	for _, test := range tests {
		t.Run(fmt.Sprintf("Test_SignUp_SignIn_IsAdmin_HappyPath №%d", i), func(t *testing.T) {
			respSignUp, err := st.AuthClient.SignUp(ctx, &ssov1.SignUpRequest{
				Name:     test.name,
				Email:    test.email,
				Password: test.password,
				IsAdmin:  test.isAdmin,
			})
			require.NoError(t, err)
			assert.NotEmpty(t, respSignUp.GetUserId())

			respSignIn, err := st.AuthClient.SignIn(ctx, &ssov1.SignInRequest{
				Email:    test.email,
				Password: test.password,
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
			assert.Equal(t, test.email, claims["email"].(string))
			assert.Equal(t, appID, int(claims["app_id"].(float64)))

			const deltaSeconds = 1
			assert.InDelta(t, loginTime.Add(st.Cfg.TokenTTL).Unix(), claims["exp"].(float64), deltaSeconds)

			userID := respSignUp.GetUserId()
			respIsAdmin, err := st.AuthClient.IsAdmin(ctx, &ssov1.IsAdminRequest{UserId: userID})
			require.NoError(t, err)
			assert.Equal(t, test.isAdmin, respIsAdmin.GetIsAdmin())
			i++
		})
	}
}

func Test_SignUp_FailCases(t *testing.T) {
	ctx, st := suite.NewSuite(t)

	i := 1
	t.Run(fmt.Sprintf("Test_SignUp_DuplicateEmail №%d", i), func(t *testing.T) {
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

		respSignUp, err = st.AuthClient.SignUp(ctx, &ssov1.SignUpRequest{
			Name:     name,
			Email:    email,
			Password: password,
			IsAdmin:  isAdmin,
		})
		require.Error(t, err)
		assert.Empty(t, respSignUp.GetUserId())
		assert.ErrorContains(t, err, "user already exists")
	})

	tests := []struct {
		name        string
		email       string
		password    string
		isAdmin     bool
		expectedErr string
	}{
		{
			name:        "Register with empty Password",
			email:       gofakeit.Email(),
			password:    "",
			isAdmin:     gofakeit.Bool(),
			expectedErr: "password is required",
		},
		{
			name:        "Register with empty Email",
			email:       "",
			password:    randomFakePassword(),
			isAdmin:     gofakeit.Bool(),
			expectedErr: "email is required",
		},
		{
			name:        "",
			email:       gofakeit.Email(),
			password:    randomFakePassword(),
			isAdmin:     gofakeit.Bool(),
			expectedErr: "name is required",
		},
	}
	i = 2
	for _, test := range tests {
		t.Run(fmt.Sprintf("Test_SignUp_FailCases №%d", i), func(t *testing.T) {
			respSignUp, err := st.AuthClient.SignUp(ctx, &ssov1.SignUpRequest{
				Name:     test.name,
				Email:    test.email,
				Password: test.password,
				IsAdmin:  test.isAdmin,
			})
			require.Error(t, err)
			assert.Empty(t, respSignUp.GetUserId())
			assert.ErrorContains(t, err, test.expectedErr)
			i++
		})
	}

}

func Test_SignIn_FailCases(t *testing.T) {
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

	tests := []struct {
		email       string
		password    string
		appID       int
		expectedErr string
	}{
		{
			//Login with empty Password
			email:       email,
			password:    "",
			appID:       appID,
			expectedErr: "password is required",
		},
		{
			//Login with empty Email
			email:       "",
			password:    password,
			appID:       appID,
			expectedErr: "email is required",
		},
		{
			//Login with empty App ID
			email:       email,
			password:    password,
			appID:       emptyAppID,
			expectedErr: "app_id is required",
		},
		{
			//Login with wrong Password
			email:       email,
			password:    randomFakePassword(),
			appID:       appID,
			expectedErr: "user not found",
		},
		{
			//Login with wrong Email
			email:       gofakeit.Email(),
			password:    password,
			appID:       appID,
			expectedErr: "user not found",
		},
		{
			//Login with wrong App ID
			email:       email,
			password:    password,
			appID:       gofakeit.IntRange(2, 100),
			expectedErr: "app not found",
		},
	}
	i := 1
	for _, test := range tests {
		t.Run(fmt.Sprintf("Test_SignIn_FailCases №%d", i), func(t *testing.T) {
			respSignIn, err := st.AuthClient.SignIn(ctx, &ssov1.SignInRequest{
				Email:    test.email,
				Password: test.password,
				AppId:    int32(test.appID),
			})
			require.Error(t, err)
			assert.Empty(t, respSignIn.GetToken())
			assert.ErrorContains(t, err, test.expectedErr)
			i++
		})
	}

}

func Test_IsAdmin_FailCases(t *testing.T) {
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

	tests := []struct {
		userId      int64
		expectedErr string
	}{
		{
			//Check if is admin with empty user id
			expectedErr: "user id is required",
		},
		{
			//Check if is admin with empty user id
			userId:      gofakeit.Int64(),
			expectedErr: "user not found",
		},
	}
	i := 1
	for _, test := range tests {
		t.Run(fmt.Sprintf("Test_IsAdmin_FailCases №%d", i), func(t *testing.T) {
			respIsAdmin, err := st.AuthClient.IsAdmin(ctx, &ssov1.IsAdminRequest{
				UserId: test.userId,
			})
			require.Error(t, err)
			assert.Empty(t, respIsAdmin.GetIsAdmin())
			assert.ErrorContains(t, err, test.expectedErr)
			i++
		})
	}
}

func randomFakePassword() string {
	return gofakeit.Password(true, true, true, true, true, passDefaultLen)
}
