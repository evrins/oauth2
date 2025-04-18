package main

import (
	"context"
	"embed"
	"flag"
	"fmt"
	"github.com/go-oauth2/oauth2/v4/errors"
	"github.com/go-oauth2/oauth2/v4/generates"
	"github.com/go-oauth2/oauth2/v4/manage"
	"github.com/go-oauth2/oauth2/v4/models"
	"github.com/go-oauth2/oauth2/v4/server"
	"github.com/go-oauth2/oauth2/v4/store"
	"github.com/go-session/session/v3"
	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
	"log"
	"net/http"
	"net/url"
)

//go:embed static
var static embed.FS

var (
	dumpvar bool
	portvar int
)

const (
	SessionKeyReturnUri      = "ReturnUri"
	SessionKeyLoggedInUserID = "LoggedInUserID"
)

func init() {
	flag.BoolVar(&dumpvar, "d", true, "Dump requests and responses")
	flag.IntVar(&portvar, "p", 9096, "the base port for the server")

	session.InitManager(session.SetSecure(false))
}

type App struct {
	ClientId     string
	ClientSecret string
	Domain       string
}

type UserInfoJson struct {
	Sub        string              `json:"sub"`
	Name       string              `json:"name"`
	Password   string              `json:"password"`
	Login      string              `json:"login"`
	Email      string              `json:"email"`
	Attributes map[string][]string `json:"attributes"`
	Role       string              `json:"role"`
}

var appList = []App{
	{
		ClientId:     "grafana_id",
		ClientSecret: "grafana_secret",
		Domain:       "http://localhost:3000/login/generic_oauth",
	},
	{
		ClientId:     "demo_client_id",
		ClientSecret: "demo_client_secret",
		Domain:       "http://localhost:9094/oauth2",
	},
}

func main() {
	flag.Parse()
	if dumpvar {
		log.Println("Dumping requests")
	}
	manager := manage.NewDefaultManager()
	manager.SetAuthorizeCodeTokenCfg(manage.DefaultAuthorizeCodeTokenCfg)

	// token store
	manager.MustTokenStorage(store.NewMemoryTokenStore())

	// generate jwt access token
	//manager.MapAccessGenerate(generates.NewJWTAccessGenerate("", []byte("00000000"), jwt.SigningMethodHS512))
	manager.MapAccessGenerate(generates.NewAccessGenerate())

	clientStore := store.NewClientStore()
	for _, app := range appList {
		clientStore.Set(app.ClientId, &models.Client{
			ID:     app.ClientId,
			Secret: app.ClientSecret,
			Domain: app.Domain,
		})
	}

	manager.MapClientStorage(clientStore)

	srv := server.NewServer(server.NewConfig(), manager)

	srv.SetPasswordAuthorizationHandler(func(ctx context.Context, clientID, username, password string) (userID string, err error) {
		if username == "test" && password == "test" {
			userID = "test"
		} else {
			err = errors.New("invalid username or password")
		}
		return
	})

	srv.SetUserAuthorizationHandler(userAuthorizeHandler)

	srv.SetInternalErrorHandler(func(err error) (re *errors.Response) {
		log.Println("Internal Error:", err.Error())
		return
	})

	srv.SetResponseErrorHandler(func(re *errors.Response) {
		log.Println("Response Error:", re.Error.Error())
	})

	var app = echo.New()
	app.Use(middleware.Logger())
	app.Use(middleware.Recover())

	if dumpvar {
		app.Use(dumpRequestMiddleware)
	}

	app.GET("/login", loginPage)
	app.POST("/login", loginHandler)
	app.Any("/auth", authHandler)
	app.Any("/oauth/authorize", func(ctx echo.Context) (err error) {
		stor, err := session.Start(ctx.Request().Context(), ctx.Response(), ctx.Request())
		if err != nil {
			return
		}

		var request = ctx.Request()
		var form url.Values
		if v, ok := stor.Get(SessionKeyReturnUri); ok {
			form = v.(url.Values)
		}
		request.Form = form

		stor.Delete(SessionKeyReturnUri)
		err = stor.Save()
		if err != nil {
			return
		}

		err = srv.HandleAuthorizeRequest(ctx.Response(), request)
		if err != nil {
			return ctx.String(http.StatusBadRequest, err.Error())
		}

		return nil
	})

	app.Any("/oauth/token", func(ctx echo.Context) (err error) {
		err = srv.HandleTokenRequest(ctx.Response(), ctx.Request())
		if err != nil {
			return
		}
		return
	})

	app.GET("/oauth/userinfo", func(ctx echo.Context) error {
		token, err := srv.ValidationBearerToken(ctx.Request())
		if err != nil {
			return ctx.JSON(http.StatusBadRequest, err.Error())
		}

		var uid = token.GetUserID()
		// todo get userinfo by uid
		var userinfo = UserInfoJson{
			Sub:   uid,
			Name:  "Marcille Hu",
			Login: "marcille",
			Email: "marcille.hu@gmail.com",
			Role:  "Admin",
		}
		return ctx.JSON(http.StatusOK, userinfo)
	})

	var addr = fmt.Sprintf(":%d", portvar)
	log.Printf("Server is running at %s.\n", addr)
	log.Printf("Point your OAuth client Auth endpoint to %s:%d%s", "http://localhost", portvar, "/oauth/authorize")
	log.Printf("Point your OAuth client Token endpoint to %s:%d%s", "http://localhost", portvar, "/oauth/token")
	log.Fatal(app.Start(addr))
}

func userAuthorizeHandler(w http.ResponseWriter, r *http.Request) (userID string, err error) {
	if dumpvar {
		_ = dumpRequest("userAuthorizeHandler", r) // Ignore the error
	}
	stor, err := session.Start(r.Context(), w, r)
	if err != nil {
		return
	}

	uid, ok := stor.Get(SessionKeyLoggedInUserID)
	if !ok {
		if r.Form == nil {
			r.ParseForm()
		}
		stor.Set(SessionKeyReturnUri, r.Form)
		stor.Save()

		w.Header().Set("Location", "/login")
		w.WriteHeader(http.StatusFound)
		return
	}

	userID = uid.(string)
	stor.Delete(SessionKeyLoggedInUserID)
	stor.Save()
	return
}

func loginPage(ctx echo.Context) (err error) {
	content, err := static.ReadFile("static/login.html")
	if err != nil {
		return
	}
	return ctx.HTML(http.StatusOK, string(content))
}

func loginHandler(ctx echo.Context) (err error) {
	stor, err := session.Start(ctx.Request().Context(), ctx.Response(), ctx.Request())
	if err != nil {
		return
	}

	var username = ctx.FormValue("username")
	var password = ctx.FormValue("password")
	if username == "test" && password == "test" {
		stor.Set(SessionKeyLoggedInUserID, username)
		err = stor.Save()
		if err != nil {
			return
		}

		return ctx.Redirect(http.StatusFound, "/auth")
	} else {
		return ctx.String(http.StatusUnauthorized, "Invalid username or password")
	}

}

func authHandler(ctx echo.Context) (err error) {
	stor, err := session.Start(nil, ctx.Response(), ctx.Request())
	if err != nil {
		return
	}

	if _, ok := stor.Get(SessionKeyLoggedInUserID); !ok {
		return ctx.Redirect(http.StatusFound, "/login")
	}

	content, err := static.ReadFile("static/auth.html")
	if err != nil {
		return
	}
	return ctx.HTML(http.StatusOK, string(content))
}
