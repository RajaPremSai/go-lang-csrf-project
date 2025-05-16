package server

import(
	"log"
	"net/http"
	"github.com/rajapremsai/go-lang-csrf-project/middleware"
)



func StartServer(hostname string , port string)error{
	host:=hostname + ":" + port
	log.Printf("listening on : %d",host)

	handler :=middleware.NewHandler()

	http.Handle("/",handler)
	return http.ListenAndServe(host,nil)
}
