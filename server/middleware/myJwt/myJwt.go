package myJwt

import (
	"crypto/rsa"
	"errors"
	"io/ioutil"
	"log"
	"time"

	"github.com/dgrijalva/jwt-go"
	jwt "github.com/dgrijalva/jwt-go"
	"github.com/rajapremsai/go-lang-csrf-project/db"
	"github.com/rajapremsai/go-lang-csrf-project/db/models"
)

const(
	privKeyPath="keys/app.rsa"
	pubKeyPath="keys/app.rsa.pub"
)

func InitJWT()error{
	signBytes,err := ioutil.ReadFile(privKeyPath)
	if err!=nil{
		return err
	}
	signkey , err := jwt.ParseRSAPrivateKeyFromPEM(signBytes)
	if err!=nil{
		return err
	}

	verifyBytes,err :=ioutil.ReadFile(pubKeyPath)
	if err!=nil{
		return err
	}
	verifyKey , err=jwt.ParseRSAPublicKeyFromPEM(verifyBytes)
	if err!=nil{
		return err
	}
	return nil
}


func CreateNewTokens(uuid string,role string)(authTokenString,refreshTokenString,csrfSecret string ,err error){
	//Generating CSRF Secret
	csrfSecret,err = models.GenerateCSRFSecret()
	if err!=nil{
		return 
	}
	//Generating the refresh token
	refreshTokenString,err = createRefreshTokenString(uuid,role,csrfSecret)
	//generating the auth token
	authTokenString,err = createAuthTokenString(uuid,role,csrfSecret)
	if err!=nil{
		return
	}
	return
}

func CheckAndRefreshTokens()(){

}

func createAuthTokenString(uuid string,role string,csrfSecret string)(authTokenString,err error){
	authTokenExp :=time.Now().Add(models.AuthTokenValidTime).Unix()
	authClaims := models.TokenClaims{
		jwt.StandardClaims{
			Subject:uuid,
			ExpiresAt:authTokenExp,

		},
		role,
		csrfSecret,
	}
	authJwt :=jwt.NewWithClaims(jwt.GetSigningMethod("RS256"),authClaims)
	authTokenString,err = authJwt.SignedString(signKey)
	return 
}

func createRefreshTokenString(uuid string , role string , csrfString string)(refreshTokenString string , err error){

	refreshTokenExp := time.Now().Add(models.RefreshTokenValidTime).Unix()
	refreshJti , err := db.StoreRefreshToken()
	if err!=nil{
		return
	}
	refreshClaims :=models.TokenClaims{
		jwt.StandardClaims{
			id:refreshJti,
			Subject:uuid,
			ExpiresAt:refreshTokenExp
		},
		role,
		csrfString,
	}
	refreshJwt := jwt.NewWithClaims(jwt.GetSigningMethod("RS256"),refreshClaims)
	refreshTokenString,err = refreshJwt.SignedString(signKey)
	return
}

func updateRefreshTokenExp()(){
	
}

func updateAuthTokenString()(){

}

func RevokeRefreshToken() error {
	
}

func updateRefreshTokenCsrf()(){

}

func GrabUUID()(){

}