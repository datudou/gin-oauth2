package ebay

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/gob"
	"encoding/json"
	"fmt"
	goauth "google.golang.org/api/oauth2/v2"
	"net/http"
	"os"

	"github.com/gin-contrib/sessions"
	"github.com/gin-contrib/sessions/cookie"
	"github.com/gin-gonic/gin"
	"github.com/golang/glog"
	//goauth "google.golang.org/api/oauth2/v2"

	"google.golang.org/api/option"

	"golang.org/x/oauth2"
)

var ENDPOINT = oauth2.Endpoint{
	AuthURL:  "https://auth.ebay.com/oauth2/authorize",
	TokenURL: "https://api.ebay.com/identity/v1/oauth2/token",
}

// Credentials stores google client-ids.
type Credentials struct {
	ClientID     string `json:"app_id"`
	ClientSecret string `json:"cert_id"`
}

const (
	stateKey  = "state"
	sessionID = "ginoauth_ebay_key"
)

var (
	conf  *oauth2.Config
	store sessions.Store
)

func init() {
	gob.Register(goauth.Userinfo{})
}

func randToken() string {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		glog.Fatalf("[Gin-OAuth] Failed to read rand: %v", err)
	}
	return base64.StdEncoding.EncodeToString(b)
}

// Setup the authorization path
func Setup(redirectURL, credFile string, scopes []string, secret []byte) {
	store = cookie.NewStore(secret)

	var c Credentials
	file, err := os.ReadFile(credFile)
	if err != nil {
		glog.Fatalf("[Gin-OAuth] File error: %v", err)
	}
	if err := json.Unmarshal(file, &c); err != nil {
		glog.Fatalf("[Gin-OAuth] Failed to unmarshal client credentials: %v", err)
	}

	conf = &oauth2.Config{
		ClientID:     c.ClientID,
		ClientSecret: c.ClientSecret,
		RedirectURL:  redirectURL,
		Scopes:       scopes,
		Endpoint:     ENDPOINT,
	}
}

func Session(name string) gin.HandlerFunc {
	return sessions.Sessions(name, store)
}

func LoginHandler(ctx *gin.Context) {
	stateValue := randToken()
	session := sessions.Default(ctx)
	session.Set(stateKey, stateValue)
	session.Save()
	ctx.Writer.Write([]byte(`
	<html>
		<head>
			<title>Ebay </title>
		</head>
	  <body>
			<a href='` + GetLoginURL(stateValue) + `'>
				<button>Login with Ebay!</button>
			</a>
		</body>
	</html>`))
}

func GetLoginURL(state string) string {
	return conf.AuthCodeURL(state)
}

func Auth() gin.HandlerFunc {
	return func(ctx *gin.Context) {
		// Handle the exchange code to initiate a transport.
		session := sessions.Default(ctx)

		existingSession := session.Get(sessionID)
		if userInfo, ok := existingSession.(goauth.Userinfo); ok {
			ctx.Set("user", userInfo)
			ctx.Next()
			return
		}

		retrievedState := session.Get(stateKey)
		if retrievedState != ctx.Query(stateKey) {
			ctx.AbortWithError(http.StatusUnauthorized, fmt.Errorf("invalid session state: %s", retrievedState))
			return
		}

		tok, err := conf.Exchange(context.TODO(), ctx.Query("code"))
		if err != nil {
			ctx.AbortWithError(http.StatusBadRequest, fmt.Errorf("failed to exchange code for oauth token: %w", err))
			return
		}
		fmt.Println(tok)

		oAuth2Service, err := goauth.NewService(ctx, option.WithTokenSource(conf.TokenSource(ctx, tok)))
		if err != nil {
			glog.Errorf("[Gin-OAuth] Failed to create oauth service: %v", err)
			ctx.AbortWithError(http.StatusInternalServerError, fmt.Errorf("failed to create oauth service: %w", err))
			return
		}

		userInfo, err := oAuth2Service.Userinfo.Get().Do()
		if err != nil {
			glog.Errorf("[Gin-OAuth] Failed to get userinfo for user: %v", err)
			ctx.AbortWithError(http.StatusInternalServerError, fmt.Errorf("failed to get userinfo for user: %w", err))
			return
		}

		ctx.Set("user", userInfo)

		session.Set(sessionID, userInfo)
		if err := session.Save(); err != nil {
			glog.Errorf("[Gin-OAuth] Failed to save session: %v", err)
			ctx.AbortWithError(http.StatusInternalServerError, fmt.Errorf("failed to save session: %v", err))
			return
		}
	}
}
