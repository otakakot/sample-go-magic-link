package main

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

const secret = "secret"

const login = `<!DOCTYPE html>
<html lang="en">

<head>
    <title>Login</title>
</head>

<body>
    <form method="POST" action="/">
        <label for="email">Email</label>
        <input type="email" name="email" id="email">
        <button type="submit">Login</button>
    </form>
</body>

</html>
`

func Handler(rw http.ResponseWriter, req *http.Request) {
	switch req.Method {
	case http.MethodGet:
		rw.Write([]byte(login))
	case http.MethodPost:
		schema := "http"

		if req.URL.Scheme != "" {
			schema = req.URL.Scheme
		}

		// TODO: メールのバリデーション

		// TODO: メールの存在確認

		println(req.FormValue("email"))

		now := time.Now()

		claims := jwt.MapClaims{
			"iss": schema + "://" + req.Host,
			"sub": req.FormValue("email"),
			"exp": now.Add(time.Hour).Unix(),
			"iat": now.Unix(),
		}

		token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)

		tokenStr, _ := token.SignedString([]byte(secret))

		link := schema + "://" + req.Host + "/link?token=" + tokenStr

		println(link)

		// TODO: メールを送信

		rw.Write([]byte(link))
	}
}

func Link(rw http.ResponseWriter, req *http.Request) {
	tokenStr := req.FormValue("token")

	token, err := jwt.Parse(tokenStr, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method")
		}

		return []byte(secret), nil
	})
	if err != nil {
		slog.Error(err.Error())

		http.Error(rw, "invalid token", http.StatusUnauthorized)

		return
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok && !token.Valid {
		slog.Error("invalid token")

		http.Error(rw, "invalid token", http.StatusUnauthorized)

		return
	}

	email, ok := claims["sub"].(string)
	if !ok {
		http.Error(rw, "invalid token", http.StatusUnauthorized)

		return
	}

	println(email)

	rw.Write([]byte(email))
}

func main() {
	port := cmp.Or(os.Getenv("PORT"), "8080")

	hdl := http.NewServeMux()

	hdl.HandleFunc("/", Handler)

	hdl.HandleFunc("/link", Link)

	srv := &http.Server{
		Addr:              fmt.Sprintf(":%s", port),
		Handler:           hdl,
		ReadHeaderTimeout: 30 * time.Second,
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)

	defer stop()

	go func() {
		slog.Info("start server listen")

		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			panic(err)
		}
	}()

	<-ctx.Done()

	slog.Info("start server shutdown")

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)

	defer cancel()

	if err := srv.Shutdown(ctx); err != nil {
		panic(err)
	}

	slog.Info("done server shutdown")
}
