package user

import (
	"database/sql"
	"go-golangra/pkg/auth"
	"go-golangra/pkg/database"
	"go-golangra/pkg/jwt"
	"net/http"

	"github.com/gin-gonic/gin"
)

type LUser struct {
	ID        uint64 `json:"id"`
	Username  string `json:"username"`
	Email     string `json:"email"`
	CreatedAt string `json:"created_at"`
}

type UpdateUser struct {
	ID       uint64 `json:"id"`
	Username string `json:"username"`
	Email    string `json:"email"`
	Password string `json:"password"`
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
	c.JSON(http.StatusOK, gin.H{"message": "Get list user successfully", "data": users})
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

	c.JSON(http.StatusOK, gin.H{"message": "Get detail user successfully", "data": user})
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
	hash, err := auth.HashPassword(body.Password)

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
