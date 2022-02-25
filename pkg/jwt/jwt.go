package jwt

import (
	"go-privy/pkg/database"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/gin-gonic/gin"
	"github.com/twinj/uuid"
)

type TokenDetails struct {
	AccessToken  string
	RefreshToken string
	AccessId     string
	AtExpires    int64
	RtExpires    int64
}

type AccessDetails struct {
	UserId uint64
}

var jwtKey = []byte("go-secret-key")
var jwtKeyRefresh = []byte("go-secret-key-refresh")

func CreateJwt(id int32, email string) (*TokenDetails, error) {
	var err error
	td := &TokenDetails{}
	td.AtExpires = time.Now().Add(time.Minute * 15).Unix()
	td.RtExpires = time.Now().Add(time.Hour * 24 * 7).Unix()
	td.AccessId = uuid.NewV4().String()

	// Creating Access token
	atClaims := jwt.MapClaims{}
	atClaims["authorized"] = true
	atClaims["i"] = id
	atClaims["e"] = email
	atClaims["a"] = td.AccessId
	atClaims["exp"] = td.AtExpires
	at := jwt.NewWithClaims(jwt.SigningMethodHS256, atClaims)
	td.AccessToken, err = at.SignedString(jwtKey)
	if err != nil {
		return nil, err
	}

	// Creating Refresh token
	rfClaims := jwt.MapClaims{}
	rfClaims["i"] = id
	rfClaims["e"] = email
	rfClaims["a"] = td.AccessId
	rfClaims["exp"] = td.RtExpires
	rt := jwt.NewWithClaims(jwt.SigningMethodHS256, rfClaims)
	td.RefreshToken, err = rt.SignedString(jwtKeyRefresh)
	if err != nil {
		return nil, err
	}

	return td, nil
}

func CreateAuth(id int32, td *TokenDetails, c *gin.Context) error {
	_, err := database.DB.Exec("INSERT INTO token (userId, accessId, refresh_token) VALUES (?,?,?)", id, td.AccessId, td.RefreshToken)

	if err != nil {
		return err
	}

	return nil
}
