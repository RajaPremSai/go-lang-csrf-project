package myJwt

import (
	"crypto/rsa"
	"errors"
	"io/ioutil"
	"log"
	"time"

	// "github.com/dgrijalva/jwt-go"
	jwt "github.com/dgrijalva/jwt-go"
	"github.com/rajapremsai/go-lang-csrf-project/db"
	"github.com/rajapremsai/go-lang-csrf-project/db/models"
)

const (
	privKeyPath="keys/app.rsa"
	pubKeyPath="keys/app.rsa.pub"
)

var (
	verifyKey *rsa.PublicKey
	signKey   *rsa.PrivateKey
)



func InitJWT() error{
	signBytes, err := ioutil.ReadFile(privKeyPath)
	if err != nil {
		return err
	}

	signKey, err = jwt.ParseRSAPrivateKeyFromPEM(signBytes)
	if err != nil {
		return err
	}

	verifyBytes, err := ioutil.ReadFile(pubKeyPath)
	if err != nil {
		return err
	}

	verifyKey, err = jwt.ParseRSAPublicKeyFromPEM(verifyBytes)
	if err != nil {
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

func CheckAndRefreshTokens(oldAuthTokenString string,oldRefreshTokenString string,oldCsrfSecret string)(newAuthTokenString,newRefreshTokenString, newCsrfSecret string,err error){

	if oldCsrfSecret==""{
		log.Println("No CSRF Token!!")
		err=errors.New("Unauthorized")
		return 
	}
	authToken,err := jwt.ParseWithClaims(oldAuthTokenString,&models.TokenClaims{},func(token *jwt.Token) (interface{},error) {
		return verifyKey,nil
	})

	authTokenClaims,ok := authToken.Claims.(*models.TokenClaims)
	if !ok{
		return
	}

	if oldCsrfSecret !=authTokenClaims.Csrf{
		log.Println("CSRF token doesn't match jwt!!")
		err =errors.New("Unauthorized")
		return
	}

	if authToken.Valid{
		log.Println("Auth Token is valid")

		newCsrfSecret=authTokenClaims.Csrf

		newRefreshTokenString,err=updateRefreshTokenExp(oldRefreshTokenString)
		newAuthTokenString=oldAuthTokenString
		return
	}else if ve,ok :=err.(*jwt.ValidationError); ok{
		log.Println("Auth token is valid")
		if ve.Errors&(jwt.ValidationErrorExpired)!=0{
			log.Println("Auth Token is expired")

			newAuthTokenString,newCsrfSecret,err=updateAuthTokenString(oldRefreshTokenString,oldAuthTokenString)

			if err!=nil{
				return 
			}

			newRefreshTokenString,err=updateRefreshTokenExp(oldRefreshTokenString)

			if err!=nil{
				return
			}

			newRefreshTokenString,err=updateRefreshTokenCsrf(newRefreshTokenString,newCsrfSecret)
			return
		}else{
			log.Print("error in auth token")
			err = errors.New("Error in the auth token")
			return
		}
	}else{
		log.Println("Error in the auth token")
		err = errors.New("Error in the auth token")
		return
	}
	err=errors.New("Unauthorized")
	return
}

func createAuthTokenString(uuid string,role string,csrfSecret string)(authTokenString string,err error){
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
	refreshClaims := models.TokenClaims{
		jwt.StandardClaims{
			Id:refreshJti,
			Subject:uuid,
			ExpiresAt:refreshTokenExp,
		},
		role,
		csrfString,
	}

	refreshJwt := jwt.NewWithClaims(jwt.GetSigningMethod("RS256"),refreshClaims)
	refreshTokenString,err = refreshJwt.SignedString(signKey)
	return
}

func updateRefreshTokenExp(oldRefreshTokenString string)(newRefreshTokenString string,err error){
	refreshToken, err := jwt.ParseWithClaims(oldRefreshTokenString,&models.TokenClaims{},func(token *jwt.Token)(interface{},error){
		return verifyKey,nil
	})
	oldRefreshTokenClaims,ok := refreshToken.Claims.(*models.TokenClaims)
	if !ok{
		return
	}
	refreshTokenExp := time.Now().Add(models.RefreshTokenValidTime).Unix()
	refreshClaims :=models.TokenClaims{
		jwt.StandardClaims{
			Id:        oldRefreshTokenClaims.StandardClaims.Id, // jti
			Subject:   oldRefreshTokenClaims.StandardClaims.Subject,
			ExpiresAt: refreshTokenExp,
		},
		oldRefreshTokenClaims.Role,
		oldRefreshTokenClaims.Csrf,
	}
	refreshJwt :=jwt.NewWithClaims(jwt.GetSigningMethod("RS256"),refreshClaims)

	newRefreshTokenString,err=refreshJwt.SignedString(signKey)
	return
}

func updateAuthTokenString(refreshTokenString string, oldAuthTokenString string) (newAuthTokenString, csrfSecret string, err error) {
	refreshToken, err := jwt.ParseWithClaims(refreshTokenString, &models.TokenClaims{}, func(token *jwt.Token) (interface{}, error) {
		return verifyKey, nil
	})
	refreshTokenClaims, ok := refreshToken.Claims.(*models.TokenClaims)
	if !ok {
		err = errors.New("error reading JWT claims")
		return
	}

	if db.CheckRefreshToken(refreshTokenClaims.StandardClaims.Id) {
		if refreshToken.Valid {
			authToken, _ := jwt.ParseWithClaims(oldAuthTokenString, &models.TokenClaims{}, func(token *jwt.Token) (interface{}, error) {
				return verifyKey, nil
			})
			oldAuthTokenClaims, ok := authToken.Claims.(*models.TokenClaims)
			if !ok {
				err = errors.New("Error reading jwt claims")
				return
			}

			csrfSecret, err = models.GenerateCSRFSecret()
			if err != nil {
				return
			}

			newAuthTokenString, err = createAuthTokenString(oldAuthTokenClaims.StandardClaims.Subject, oldAuthTokenClaims.Role, csrfSecret)
			return
		} else {
			log.Println("Refresh Token has expired")
			db.DeleteRefreshToken(refreshTokenClaims.StandardClaims.Id)

			err = errors.New("Unauthorized")
			return
		}
	} else {
		log.Println("Refresh token has been revoked")
		err = errors.New("Unauthorized")
		return
	}
}

func RevokeRefreshToken(refreshTokenString string) error { //deletes the refresh token
	//use the refresh token string that this function will receive to get our refresh token
	refreshToken, err := jwt.ParseWithClaims(refreshTokenString, &models.TokenClaims{}, func(token *jwt.Token) (interface{}, error) {
		return verifyKey, nil
	})
	if err != nil {
		return errors.New("Could not parse refresh token with claims")
	}
	//use the refresh token to get the refresh token claims
	refreshTokenClaims, ok := refreshToken.Claims.(*models.TokenClaims)
	if !ok {
		return errors.New("Could not refresh token claims")
	}

	//Deleting the refresh token using the method in db package
	db.DeleteRefreshToken(refreshTokenClaims.StandardClaims.Id)
	return nil
}

func updateRefreshTokenCsrf(oldRefreshTokenString string, newCsrfString string) (newRefreshTokenString string, err error) {
	//Get access to refresh token by using the parswithclaims function
	refreshToken, err := jwt.ParseWithClaims(oldRefreshTokenString, &models.TokenClaims{}, func(token *jwt.Token) (interface{}, error) {
		return verifyKey, nil
	})
	//get access to the refresh token claims
	oldRefreshTokenClaims, ok := refreshToken.Claims.(*models.TokenClaims)
	if !ok {
		return
	}

	//refreshclaims
	refreshClaims := models.TokenClaims{
		jwt.StandardClaims{
			Id:        oldRefreshTokenClaims.StandardClaims.Id,
			Subject:   oldRefreshTokenClaims.StandardClaims.Subject,
			ExpiresAt: oldRefreshTokenClaims.StandardClaims.ExpiresAt,
		},
		oldRefreshTokenClaims.Role,
		newCsrfString,
	}

	//new refresh jwt
	refreshJwt := jwt.NewWithClaims(jwt.GetSigningMethod("RS256"), refreshClaims)

	//new refresh token string
	newRefreshTokenString, err = refreshJwt.SignedString(signKey)
	return
}

func GrabUUID(authTokenString string) (string, error) {
	authToken, _ := jwt.ParseWithClaims(authTokenString, &models.TokenClaims{}, func(token *jwt.Token) (interface{}, error) {
		return "", errors.New("Error fetching claims")
	})
	authTokenClaims, ok := authToken.Claims.(*models.TokenClaims)
	if !ok {
		return "", errors.New("Error fetching claims")
	}
	return authTokenClaims.StandardClaims.Subject, nil
}