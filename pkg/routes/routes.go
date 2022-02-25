package routes

import (
	"go-privy/pkg/auth"
	"go-privy/pkg/middleware"
	"go-privy/pkg/saldo"
	"go-privy/pkg/user"

	"github.com/gin-gonic/gin"
)

func Routes() *gin.Engine {
	router := gin.Default()

	v1 := router.Group("/api/v1")
	{
		// Auth
		v1.POST("/login", auth.Login)
		v1.POST("/logout", middleware.AuthMiddleware(), auth.Logout)
		v1.POST("/register", auth.Register)
		v1.POST("/refresh", auth.Refresh)

		// User
		v1.GET("/user", middleware.AuthMiddleware(), user.ListUser)
		v1.GET("/user/me", middleware.AuthMiddleware(), user.UserbyId)
		v1.PUT("/user", middleware.AuthMiddleware(), user.EditUser)
		v1.DELETE("/user/:id", middleware.AuthMiddleware(), user.DeleteUser)

		// Saldo
		v1.POST("/saldo", middleware.AuthMiddleware(), saldo.SelfAddSaldo)
		v1.POST("/transfer", middleware.AuthMiddleware(), saldo.SelfTransfer)
	}

	return router
}
