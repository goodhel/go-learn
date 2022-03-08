package jwt

import (
	"fmt"
	"go-golangra/pkg/database"
	"net/http"
	"strconv"
	"strings"
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
	UserId   uint64
	AccessId string
}

var jwtKey = []byte("go-secret-key")
var jwtKeyRefresh = []byte("go-secret-key-refresh")

func CreateJwt(id uint64, email string) (*TokenDetails, error) {
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

func CreateAuth(id uint64, td *TokenDetails, c *gin.Context) error {
	_, err := database.DB.Exec("INSERT INTO token (userId, accessId, refresh_token) VALUES (?,?,?)", id, td.AccessId, td.RefreshToken)

	if err != nil {
		return err
	}

	return nil
}

// Extrac token from the Header
func ExtracToken(r *http.Request) string {
	bearerToken := r.Header.Get("Authorization")
	// normally Authorization Token Bearer askjdklasjd
	strArr := strings.Split(bearerToken, " ")
	if len(strArr) == 2 {
		return strArr[1]
	}

	return ""
}

// Verify token signin method
func VerifyToken(r *http.Request) (*jwt.Token, error) {
	tokenString := ExtracToken(r)
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		//Make sure that the token method conform to "SigningMethodHMAC"
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return jwtKey, nil
	})

	if err != nil {
		return nil, err
	}

	return token, nil
}

// Check Validity of the token
func TokenValid(r *http.Request) error {
	token, err := VerifyToken(r)
	if err != nil {
		return err
	}

	if _, ok := token.Claims.(jwt.Claims); !ok && !token.Valid {
		return err
	}

	return nil
}

// Extract Token Metadata
func ExtracTokenMetadata(r *http.Request) (*AccessDetails, error) {
	token, err := VerifyToken(r)
	if err != nil {
		return nil, err
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if ok && token.Valid {
		accessId, ok := claims["a"].(string)
		if !ok {
			return nil, err
		}
		userId, err := strconv.ParseUint(fmt.Sprintf("%.f", claims["i"]), 10, 64)
		if err != nil {
			return nil, err
		}

		return &AccessDetails{
			UserId:   userId,
			AccessId: accessId,
		}, nil
	}

	return nil, err
}

func FetchAuth(authD *AccessDetails) (uint64, error) {
	var userId uint64

	err := database.DB.QueryRow("SELECT userId FROM token WHERE accessId = ? ", authD.AccessId).Scan(&userId)
	if err != nil {
		return 0, err
	}

	return userId, nil
}
