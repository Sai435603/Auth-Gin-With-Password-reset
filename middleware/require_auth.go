package middleware

import (
	"Auth-gin-with-password-reset/auth"
	"net/http"

	"github.com/gin-gonic/gin"
)

func AuthMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		accessToken, err := c.Cookie("access_token")
		if err != nil || accessToken == "" {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
				"error": "unauthorized",
			})
			return
		}

		claims, err := auth.ValidateToken(accessToken, "access")
		if err != nil {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
				"error": "invalid or expired access token",
			})
			return
		}

		c.Set("userID", claims.UserID)
		c.Next()
	}
}
