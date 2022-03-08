package auth

import (
	"fmt"
	"go-golangra/pkg/database"
	"go-golangra/pkg/jwt"
	"net/http"
	"strconv"

	jwt_go "github.com/dgrijalva/jwt-go"
	"github.com/gin-gonic/gin"
	"golang.org/x/crypto/bcrypt"
)

type User struct {
	ID        uint64 `json:"id"`
	Username  string `json:"username"`
	Email     string `json:"email"`
	Password  string `json:"password"`
	CreatedAt string `json:"created_at"`
}

type CreateUser struct {
	Username string `json:"username"`
	Email    string `json:"email"`
	Password string `json:"password"`
}

type LoginUser struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

type RefreshToken struct {
	RefreshToken string `json:"refresh_token"`
}

func Login(c *gin.Context) {
	var body LoginUser
	var user User

	// Bind Json into LoginUser
	if err := c.BindJSON(&body); err != nil {
		c.JSON(http.StatusUnprocessableEntity, gin.H{"error": "Invalid json provided"})
		return
	}

	// Check user from database
	err := database.DB.QueryRow("SELECT id, username, email, password, created_at FROM user WHERE email = ?", body.Email).Scan(&user.ID, &user.Username, &user.Email, &user.Password, &user.CreatedAt)

	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "User not found"})
		return
	}

	// Check Password between input and database
	match := CheckPassHash(body.Password, user.Password)

	if !match {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Wrong Password"})
		return
	}

	token, err := jwt.CreateJwt(user.ID, user.Email)

	if err != nil {
		c.JSON(http.StatusUnprocessableEntity, err.Error())
		return
	}

	authErr := jwt.CreateAuth(user.ID, token, &gin.Context{})

	if authErr != nil {
		c.JSON(http.StatusUnprocessableEntity, err.Error())
		return
	}

	tokens := map[string]string{
		"access_token":  token.AccessToken,
		"refresh_token": token.RefreshToken,
	}

	c.JSON(http.StatusOK, gin.H{"message": "Login succesfully", "data": tokens})

}

func Register(c *gin.Context) {
	var body CreateUser

	// Bind Json into CreateUser
	if err := c.BindJSON(&body); err != nil {
		c.JSON(http.StatusUnprocessableEntity, gin.H{"error": "Invalid json provided"})
		return
	}

	// Hash Password
	hash, err := HashPassword(body.Password)

	if err != nil {
		c.JSON(http.StatusUnprocessableEntity, gin.H{"error": "Password hashed fail"})
		return
	}

	result, err := database.DB.Exec("INSERT INTO user (username, email, password) VALUES (?,?,?)",
		body.Username, body.Email, hash)

	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Get the last id inserted
	id, err := result.LastInsertId()
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Error get last id"})
		return
	}

	c.JSON(http.StatusCreated, gin.H{"message": "Register user successfully", "data": id})
}

func HashPassword(password string) (string, error) {
	bytes, err := bcrypt.GenerateFromPassword([]byte(password), 10)
	return string(bytes), err
}

func CheckPassHash(password, hash string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))

	return err == nil
}

func Logout(c *gin.Context) {
	tokenAuth, err := jwt.ExtracTokenMetadata(c.Request)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized"})
		return
	}

	accessId := tokenAuth.AccessId

	result, err := database.DB.Exec("DELETE FROM token WHERE accessId = ?", accessId)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	affectedRows, err := result.RowsAffected()

	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	data := map[string]int64{
		"affectedRows": affectedRows,
	}

	c.JSON(http.StatusOK, gin.H{"message": "Delete user successfully", "data": data})
}

func Refresh(c *gin.Context) {
	var body RefreshToken

	if err := c.BindJSON(&body); err != nil {
		c.JSON(http.StatusUnprocessableEntity, gin.H{"error": "Invalid json provided"})
		return
	}

	// Verify Token
	var jwtKeyRefresh = []byte("go-secret-key-refresh")
	token, err := jwt_go.Parse(body.RefreshToken, func(token *jwt_go.Token) (interface{}, error) {
		//Make sure that the token method conform to "SigningMethodHMAC"
		if _, ok := token.Method.(*jwt_go.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return jwtKeyRefresh, nil
	})
	//if there is an error, the token must have expired
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Refresh token expired"})
		return
	}
	//is token valid?
	if _, ok := token.Claims.(jwt_go.Claims); !ok && !token.Valid {
		c.JSON(http.StatusUnauthorized, err)
		return
	}
	//Since token is valid
	claims, ok := token.Claims.(jwt_go.MapClaims) //the token claims should conform to MapClaims
	if ok && token.Valid {
		email, ok := claims["e"].(string) //convert the interface to string
		if !ok {
			c.JSON(http.StatusUnprocessableEntity, err)
			return
		}
		userId, err := strconv.ParseUint(fmt.Sprintf("%.f", claims["i"]), 10, 64)
		if err != nil {
			c.JSON(http.StatusUnprocessableEntity, "Error occurred")
			return
		}
		//Create new pairs of refresh and access tokens
		token, err := jwt.CreateJwt(userId, email)

		if err != nil {
			c.JSON(http.StatusUnprocessableEntity, err.Error())
			return
		}

		// Delete Old Token
		del, err := database.DB.Exec("DELETE FROM token WHERE userId = ? AND refresh_token = ?",
			userId, body.RefreshToken)
		if err != nil {
			c.JSON(http.StatusUnprocessableEntity, err.Error())
			return
		}

		fmt.Print(del)

		authErr := jwt.CreateAuth(userId, token, &gin.Context{})

		if authErr != nil {
			c.JSON(http.StatusUnprocessableEntity, err.Error())
			return
		}

		tokens := map[string]string{
			"access_token":  token.AccessToken,
			"refresh_token": token.RefreshToken,
		}
		c.JSON(http.StatusOK, gin.H{"message": "Refresh token succesfully", "data": tokens})
	} else {
		c.JSON(http.StatusUnauthorized, "refresh expired")
	}
}
