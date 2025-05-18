package server

import (
	"log"
	"net/http"

	"github.com/rajapremsai/go-lang-csrf-project/server/middleware"
)



func StartServer(hostname string , port string)error{
	host:=hostname + ":" + port
	log.Printf("listening on : %s %s",hostname,port)

	handler :=middleware.NewHandler()

	http.Handle("/",handler)
	return http.ListenAndServe(host,nil)
}
