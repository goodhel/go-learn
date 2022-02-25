package auth

import (
	"go-privy/pkg/database"
	"go-privy/pkg/jwt"
	"net/http"

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
