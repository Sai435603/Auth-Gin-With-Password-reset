package main

import (
	"Auth-gin-with-password-reset/auth"
	"Auth-gin-with-password-reset/config"
	"Auth-gin-with-password-reset/handlers"
	"Auth-gin-with-password-reset/middleware"
	"log"
	"os"

	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
	"github.com/joho/godotenv"
)

func main() {
	_ = godotenv.Load()

	if err := auth.Init(os.Getenv("SECRET_KEY")); err != nil {
		log.Fatal(err)
	}

	err := config.ConnectDB()
	if err != nil {
		log.Fatal(err)
	}

	router := gin.Default()

	frontendURL := os.Getenv("FRONTEND_URL")
	if frontendURL == "" {
		frontendURL = "http://localhost:3000"
	}

	router.Use(cors.New(cors.Config{
		AllowOrigins:     []string{frontendURL},
		AllowMethods:     []string{"GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"},
		AllowHeaders:     []string{"Origin", "Content-Type", "Accept", "Authorization"},
		AllowCredentials: true,
	}))

	authRoutes := router.Group("/auth")
	{
		authRoutes.POST("/register", handlers.Register)
		authRoutes.POST("/login", handlers.Login)
		authRoutes.POST("/refresh", handlers.Refresh)
		authRoutes.POST("/logout", handlers.Logout)
	}

	api := router.Group("/api")
	api.Use(middleware.AuthMiddleware())
	{
		api.GET("/me", handlers.Me)
	}

	if err := router.Run(":8080"); err != nil {
		log.Fatal(err)
	}
}
