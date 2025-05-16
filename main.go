package main

import(
"log"
"github.com/rajapremsai/go-lang-csrf-project/db"
"github.com/rajapremsai/go-lang-csrf-project/server"
"github.com/rajapremsai/go-lang-csrf-project/server/middleware/myJwt"
)

var host="localhost"
var port="9000"

func main(){
	db.InitDB()
	jwtErr :=myJwt.InitJWT()
	if jwtErr !=nil{
		log.Println("Error Initializing JWT!!")
		log.Fatal(jwtErr)
	}

	serverErr := server.StartServer(host,port)
	if serverErr!=nil{
		log.Println("Error Initializing JWT!!")
		log.Fatal(serverErr)
	}
}