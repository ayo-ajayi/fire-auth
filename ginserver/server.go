package ginserver

import (
	"context"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/gorilla/sessions"
	"github.com/joho/godotenv"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
)

func init() {
	if _, err := os.Stat(".env"); err == nil {
		if err := godotenv.Load(".env"); err != nil {
			log.Println(err)
		}
	}

	googleOauthConfig = &oauth2.Config{
		RedirectURL:  "http://localhost:8080/callback",
		ClientID:     os.Getenv("CLIENT_ID"),
		ClientSecret: os.Getenv("CLIENT_SECRET"),
		Scopes:       []string{"https://www.googleapis.com/auth/userinfo.email", "https://www.googleapis.com/auth/userinfo.profile"},
		Endpoint:     google.Endpoint,
	}
	store = sessions.NewCookieStore([]byte(os.Getenv("SESSION_SECRET")))
	PORT = os.Getenv("PORT")
}

var store *sessions.CookieStore
var googleOauthConfig *oauth2.Config
var PORT string

func Gin() {
	router := gin.Default()
	router.GET("/", handleHome)
	router.GET("/login", handleLogin)
	router.GET("/callback", handleCallback)
	router.NoRoute(func(c *gin.Context) {
		c.JSON(http.StatusNotFound, gin.H{"error": "Not Found"})
	})
	log.Fatal(router.Run(":" + PORT))
}

func handleHome(c *gin.Context) {
	html := `
	<!DOCTYPE html>
	<html><head><title>Not Found</title></head>
	<body>
	<a href="/login">Google Sign In</a>
	</body>
	</html>
	`
	c.Writer.WriteString(html)
}

func generateRandomState() string {
	return uuid.New().String()
}

func handleLogin(c *gin.Context) {
	session, err := store.New(c.Request, "session-name")
	if err != nil {
		c.AbortWithStatus(http.StatusInternalServerError)
		c.String(http.StatusInternalServerError, "Internal server error")
		return
	}
	session.Values["randomstate"] = generateRandomState()
	if err = session.Save(c.Request, c.Writer); err != nil {
		c.AbortWithStatus(http.StatusInternalServerError)
		c.String(http.StatusInternalServerError, "Internal server error")
		return
	}
	randomState := session.Values["randomstate"].(string)
	url := googleOauthConfig.AuthCodeURL(randomState)
	c.Redirect(http.StatusTemporaryRedirect, url)
}

func handleCallback(c *gin.Context) {
	session := getSession(c)
	randomState, ok := session.Values["randomstate"].(string)
	if !ok || c.DefaultQuery("state", "") != randomState {
		fmt.Println("state is not valid")
		c.Redirect(http.StatusTemporaryRedirect, "/")
		return
	}
	session.Options.MaxAge = -1
	if err := session.Save(c.Request, c.Writer); err != nil {
		c.AbortWithStatus(http.StatusInternalServerError)
		c.String(http.StatusInternalServerError, "Internal server error")
		return
	}

	token, err := googleOauthConfig.Exchange(context.Background(), c.DefaultQuery("code", ""))
	if err != nil {
		fmt.Print("could not create token", err)
		c.Redirect(http.StatusTemporaryRedirect, "/")
		return
	}
	res, err := http.Get("https://www.googleapis.com/oauth2/v2/userinfo?access_token=" + token.AccessToken)
	if err != nil {
		fmt.Print("could not create get request", err)
		c.Redirect(http.StatusTemporaryRedirect, "/")
		return
	}
	defer res.Body.Close()
	content, err := io.ReadAll(res.Body)
	if err != nil {
		fmt.Print(err)
		c.Redirect(http.StatusTemporaryRedirect, "/")
		return
	}
	c.String(http.StatusOK, "response: %s", string(content))
}

func getSession(c *gin.Context) *sessions.Session {
	session, err := store.Get(c.Request, "session-name")
	if err != nil {
		c.String(http.StatusInternalServerError, "Internal server error")
		c.Abort()
	}
	return session
}
