package middleware

import (
	"net/http"
	"log"
	"github.com/justinas/alice"
	"time"
	"strings"
	"github.com/rajapremsai/go-lang-csrf-project/server/middleware/myJwt"
	"github.com/rajapremsai/go-lang-csrf-project/db"
	"github.com/rajapremsai/go-lang-csrf-project/server/templates"
)

func NewHandler() http.Handler{
	return alice.New(recoverHandler,authHandler).ThenFunc(logicHandler)
}

func recoverHandler(next http.Handler)http.Handler{
	fn :=func(w http.ResponseWriter,r *http.Request){
		defer func(){
			if err:=recover();err !=nil{
				log.Panic("Recovered Panic:%v",err)
				http.Error(w,http.StatusText(500),500)
			}
		}()
		next.ServeHTTP(w,r)
	}
	return http.HandlerFunc(fn)
}

func authHandler(next http.Handler)http.Handler{
	fn:=func(W http.ResponseWriter,r *http.Request){
		switch r.URL.PAth{
		case "/restricted","/logout","/deleteUser":
		default:
		}
	}
}

func logicHandler(w http.ResponseWriter, r *http.Request){
	switch r.URL.Path{
	case "/restricted":
		csrfSecret=grabCsrfFromReq(r)
		templates.RenderTemplate(w,"restricted",&templates.RestrictedPage{csrfSecret,"Hello Prem"})
	case "/login":
		switch r.Method{
		case "GET":
		case "POST":
		default:
		}
	case "/logout":
	case "/deleteUser":
	default:
	}
}

func nullifyTokenCookies(w *http.ResponseWriter,r *http.Request){
	authCookie :=http.Cookie{
		Name:"AuthToken",
		Value:"",
		Expires:time.Now().Add(-1000*time.Hour),
		HttpOnly: true,
	}
	http.SetCookie(*w,&authCookie)
	refreshCookie :=http.Cookie{
		Name:"RefreshToken",
		Value:"",
		Expires:time.Now().Add(-1000*time.Hour)
		HttpOnly: true,
	}
	http.SetCookie(*w,&refreshCookie)

	RefreshCookie,refreshErr := r.Cookie("RefreshToken")
	if refreshErr == http.ErrNoCookie{
		return //do nothing
	}else if refreshErr !=nil{
		log.Panic("Panic : %+v" , refreshErr)
		http.Error(*w,httpStatusText(500),500)
	}
	myJwt.RevokeRefreshToken(RefreshCookie.Value)
}

func setAuthAndRefreshCookies(w *http.ResponseWriter,authTokenString string,refreshTokenString string){
	authCookie:http.Cookie{
		Name:"AuthToken"
		Value:authTokenString
		HttOnly:true
	}
	http.SetCookie(*w,&authCookie)
	refreshCookie :=http.Cookie{
		Name:"RefreshToken"
		Value:refreshTokenString
		HttpOnly: true,
	}
	http.SetCookie(*w,&refreshCookie)
}

func grabCsrfFromReq(r *http.Request) string{
	csrfFromFrom:=r.FormValue("x-CSRF-Token")

	if csrfFromFrom !=""{
		return csrfFromFrom
	}else{
		return r.Header.Get("X-CSRF-Token")
	}
}