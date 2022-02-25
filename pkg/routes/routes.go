package routes

import (
	"go-privy/pkg/auth"
	"go-privy/pkg/middleware"

	"github.com/gin-gonic/gin"
)

func Routes() *gin.Engine {
	router := gin.Default()

	v1 := router.Group("/api/v1")
	{
		// Auth
		v1.POST("/login", auth.Login)
		v1.POST("/register", auth.Register)

		// User
		v1.GET("/user", middleware.AuthMiddleware(), auth.ListUser)
		v1.GET("/user/me", middleware.AuthMiddleware(), auth.UserbyId)
		v1.PUT("/user", middleware.AuthMiddleware(), auth.EditUser)
		v1.DELETE("/user/:id", middleware.AuthMiddleware(), auth.DeleteUser)
	}

	return router
}
