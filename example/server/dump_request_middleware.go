package main

import (
	"github.com/labstack/echo/v4"
	"log"
	"net/http"
	"net/http/httputil"
)

func dumpRequest(header string, r *http.Request) error {
	data, err := httputil.DumpRequest(r, true)
	if err != nil {
		return err
	}
	log.Printf("--- %s ---", header)
	log.Println(string(data))
	return nil
}

func dumpRequestMiddleware(next echo.HandlerFunc) echo.HandlerFunc {
	return func(ctx echo.Context) (err error) {
		data, err := httputil.DumpRequest(ctx.Request(), true)
		if err != nil {
			return
		}

		log.Println(string(data))

		err = next(ctx)
		return
	}
}
