package core

import (
	"github.com/gorilla/securecookie"
	"net/http"
)

var cookieHandler = securecookie.New(
	securecookie.GenerateRandomKey(64),
	securecookie.GenerateRandomKey(32))

func getUserName(r *http.Request) (userName string) {
	if cookie, err := r.Cookie(session + "_session"); err == nil {
		cookieValue := make(map[string]string)
		if err = cookieHandler.Decode(session+"_session", cookie.Value, &cookieValue); err == nil {
			userName = cookieValue["name"]
		}
	}
	return userName
}
func setSession(userName string, w http.ResponseWriter) {
	value := map[string]string{
		"name": userName,
	}
	if encoded, err := cookieHandler.Encode(session+"_session", value); err == nil {
		cookie := &http.Cookie{
			Name:  session + "_session",
			Value: encoded,
			Path:  "/",
		}
		http.SetCookie(w, cookie)
	}
}
func clearSession(w http.ResponseWriter) {
	cookie := &http.Cookie{
		Name:   session + "_session",
		Value:  "",
		Path:   "/",
		MaxAge: -1,
	}
	http.SetCookie(w, cookie)
}
