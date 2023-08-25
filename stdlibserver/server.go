package stdlibserver

import (
	"context"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"

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

func NetHTTP() {
	http.HandleFunc("/", handleHome)
	http.HandleFunc("/login", handleLogin)
	http.HandleFunc("/callback", handleCallback)
	log.Fatal(http.ListenAndServe(":"+PORT, nil))
}

func handleHome(w http.ResponseWriter, r *http.Request) {
	html := `

	<!DOCTYPE html>
<html><head><title>Not Found</title></head>
<body>
<a href="/login">Google Sign In</a>
</body>
</html>
	
	`
	fmt.Fprint(w, html)
}

func generateRandomState() string {
	return uuid.New().String()
}


func handleLogin(w http.ResponseWriter, r *http.Request) {
	session, err:= store.New(r, "session-name")
	if err != nil {
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}
	session.Values["randomstate"] = generateRandomState()
	if err = session.Save(r, w); err != nil {
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}
	randomState := session.Values["randomstate"].(string)
	url := googleOauthConfig.AuthCodeURL(randomState)
	http.Redirect(w, r, url, http.StatusTemporaryRedirect)
}
func handleCallback(w http.ResponseWriter, r *http.Request) {
	session, err:= store.New(r, "session-name")
	if err != nil {
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}
	randomState, ok := session.Values["randomstate"].(string)
	if !ok || r.FormValue("state") != randomState {
		fmt.Println("state is not valid")
		http.Redirect(w, r, "/", http.StatusTemporaryRedirect)
		return
	}
	session.Options.MaxAge = -1
	if err := session.Save(r, w); err != nil {
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}
	token, err := googleOauthConfig.Exchange(context.Background(), r.FormValue("code"))
	if err != nil {
		fmt.Print("could not create token", err)
		http.Redirect(w, r, "/", http.StatusTemporaryRedirect)
		return
	}
	res, err := http.Get("https://www.googleapis.com/oauth2/v2/userinfo?access_token=" + token.AccessToken)
	if err != nil {
		fmt.Print("could not create get request", err)
		http.Redirect(w, r, "/", http.StatusTemporaryRedirect)
		return
	}
	defer res.Body.Close()
	content, err := io.ReadAll(res.Body)
	if err != nil {
		fmt.Print(err)
		http.Redirect(w, r, "/", http.StatusTemporaryRedirect)
		return
	}
	fmt.Fprintf(w, "response: %s", content)
}


