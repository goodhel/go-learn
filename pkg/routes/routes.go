package routes

import (
	"go-privy/pkg/auth"

	"github.com/gin-gonic/gin"
)

func Routes() *gin.Engine {
	router := gin.Default()

	v1 := router.Group("/api/v1")
	{
		v1.POST("/login", auth.Login)
		v1.POST("/register", auth.Register)
	}

	return router
}
