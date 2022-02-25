package auth

import (
	"database/sql"
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

type LUser struct {
	ID        uint64 `json:"id"`
	Username  string `json:"username"`
	Email     string `json:"email"`
	CreatedAt string `json:"created_at"`
}

type CreateUser struct {
	Username string `json:"username"`
	Email    string `json:"email"`
	Password string `json:"password"`
}

type UpdateUser struct {
	ID       uint64 `json:"id"`
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

func ListUser(c *gin.Context) {
	var users []LUser

	results, err := database.DB.Query(`SELECT id, username, email, created_at FROM user`)

	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Error get last id"})
		return
	}

	defer results.Close()

	for results.Next() {
		var usr LUser
		if err := results.Scan(&usr.ID, &usr.Username, &usr.Email, &usr.CreatedAt); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Not Found"})
			return
		}
		users = append(users, usr)
	}

	if err := results.Err(); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Not Found"})
		return
	}

	c.JSON(http.StatusOK, users)
}

func UserbyId(c *gin.Context) {
	var user LUser

	tokenAuth, err := jwt.ExtracTokenMetadata(c.Request)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized"})
		return
	}

	id := tokenAuth.UserId

	err2 := database.DB.QueryRow("SELECT id, username, email, created_at FROM user WHERE id = ?", id).Scan(&user.ID, &user.Username, &user.Email, &user.CreatedAt)

	if err2 != nil && err2 != sql.ErrNoRows {
		c.JSON(http.StatusNotFound, gin.H{"error": "User not found"})
		return
	}

	c.JSON(http.StatusOK, user)
}

func EditUser(c *gin.Context) {
	var body UpdateUser

	// Bind Json into CreateUser
	if err := c.BindJSON(&body); err != nil {
		c.JSON(http.StatusUnprocessableEntity, gin.H{"error": "Invalid json provided"})
		return
	}

	tokenAuth, err := jwt.ExtracTokenMetadata(c.Request)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized"})
		return
	}

	body.ID = tokenAuth.UserId

	// Hash Password
	hash, err := HashPassword(body.Password)

	if err != nil {
		c.JSON(http.StatusUnprocessableEntity, gin.H{"error": "Password hashed fail"})
		return
	}

	result, err := database.DB.Exec("UPDATE user SET username = ?, email = ?, password = ? WHERE id = ?",
		body.Username, body.Email, hash, body.ID)

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

	c.JSON(http.StatusOK, gin.H{"message": "Update user successfully", "data": data})
}

func DeleteUser(c *gin.Context) {
	id := c.Param("id")

	result, err := database.DB.Exec("DELETE FROM user WHERE id = ?", id)
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
