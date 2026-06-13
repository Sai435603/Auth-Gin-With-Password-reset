package handlers

import (
	"Auth-gin-with-password-reset/auth"
	"Auth-gin-with-password-reset/config"
	"Auth-gin-with-password-reset/models"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/gorm"
)

type RegisterRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

type LoginRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

type UserResponse struct {
	ID        string    `json:"id"`
	Email     string    `json:"email"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

func userToResponse(u models.User) UserResponse {
	return UserResponse{
		ID:        u.ID.String(),
		Email:     u.Email,
		CreatedAt: u.CreatedAt,
		UpdatedAt: u.UpdatedAt,
	}
}

func hashString(value string) string {
	sum := sha256.Sum256([]byte(value))
	return hex.EncodeToString(sum[:])
}

func isProduction() bool {
	return strings.ToLower(os.Getenv("APP_ENV")) == "production"
}

func cookieSameSite() http.SameSite {
	switch strings.ToLower(os.Getenv("COOKIE_SAMESITE")) {
	case "none":
		return http.SameSiteNoneMode
	case "strict":
		return http.SameSiteStrictMode
	default:
		return http.SameSiteLaxMode
	}
}

func cookieDomain() string {
	return os.Getenv("COOKIE_DOMAIN")
}

func setCookie(c *gin.Context, name, value string, maxAge int) {
	http.SetCookie(c.Writer, &http.Cookie{
		Name:     name,
		Value:    value,
		Path:     "/",
		Domain:   cookieDomain(),
		MaxAge:   maxAge,
		HttpOnly: true,
		Secure:   isProduction(),
		SameSite: cookieSameSite(),
	})
}

func clearCookie(c *gin.Context, name string) {
	http.SetCookie(c.Writer, &http.Cookie{
		Name:     name,
		Value:    "",
		Path:     "/",
		Domain:   cookieDomain(),
		MaxAge:   -1,
		HttpOnly: true,
		Secure:   isProduction(),
		SameSite: cookieSameSite(),
	})
}

func Register(c *gin.Context) {
	var req RegisterRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request body"})
		return
	}

	req.Email = strings.ToLower(strings.TrimSpace(req.Email))
	req.Password = strings.TrimSpace(req.Password)

	if req.Email == "" || req.Password == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "email and password are required"})
		return
	}

	if len(req.Password) < 8 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "password must be at least 8 characters"})
		return
	}

	var existing models.User
	err := config.DB.Where("email = ?", req.Email).First(&existing).Error
	if err == nil {
		c.JSON(http.StatusConflict, gin.H{"error": "user already exists"})
		return
	}
	if err != nil && err != gorm.ErrRecordNotFound {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "database error"})
		return
	}

	passwordHash, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to hash password"})
		return
	}

	user := models.User{
		Email:        req.Email,
		PasswordHash: string(passwordHash),
	}

	if err := config.DB.Create(&user).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to create user"})
		return
	}

	c.JSON(http.StatusCreated, gin.H{
		"message": "user registered successfully",
		"user":    userToResponse(user),
	})
}

func Login(c *gin.Context) {
	var req LoginRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request body"})
		return
	}

	req.Email = strings.ToLower(strings.TrimSpace(req.Email))
	req.Password = strings.TrimSpace(req.Password)

	var user models.User
	if err := config.DB.Where("email = ?", req.Email).First(&user).Error; err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid email or password"})
		return
	}

	if err := bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(req.Password)); err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid email or password"})
		return
	}

	accessToken, refreshToken, err := auth.GenerateToken(user.ID.String())
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to generate tokens"})
		return
	}

	// Store only the hash of the refresh token in DB.
	user.RefreshToken = hashString(refreshToken)
	if err := config.DB.Save(&user).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to save refresh token"})
		return
	}

	setCookie(c, "access_token", accessToken, 15*60)
	setCookie(c, "refresh_token", refreshToken, 7*24*60*60)

	c.JSON(http.StatusOK, gin.H{
		"message": "login successful",
		"user":    userToResponse(user),
	})
}

func Refresh(c *gin.Context) {
	refreshToken, err := c.Cookie("refresh_token")
	if err != nil || refreshToken == "" {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "refresh token missing"})
		return
	}

	claims, err := auth.ValidateToken(refreshToken, "refresh")
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid or expired refresh token"})
		return
	}

	var user models.User
	if err := config.DB.Where("id = ?", claims.UserID).First(&user).Error; err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "user not found"})
		return
	}

	if user.RefreshToken == "" || user.RefreshToken != hashString(refreshToken) {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "refresh token revoked"})
		return
	}

	newAccessToken, newRefreshToken, err := auth.GenerateToken(user.ID.String())
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to generate tokens"})
		return
	}

	user.RefreshToken = hashString(newRefreshToken)
	if err := config.DB.Save(&user).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to rotate refresh token"})
		return
	}

	setCookie(c, "access_token", newAccessToken, 15*60)
	setCookie(c, "refresh_token", newRefreshToken, 7*24*60*60)

	c.JSON(http.StatusOK, gin.H{
		"message": "token refreshed",
	})
}

func Logout(c *gin.Context) {
	refreshToken, _ := c.Cookie("refresh_token")

	if refreshToken != "" {
		claims, err := auth.ValidateToken(refreshToken, "refresh")
		if err == nil {
			config.DB.Model(&models.User{}).
				Where("id = ?", claims.UserID).
				Update("refresh_token", "")
		}
	}

	clearCookie(c, "access_token")
	clearCookie(c, "refresh_token")

	c.JSON(http.StatusOK, gin.H{
		"message": "logged out successfully",
	})
}

func Me(c *gin.Context) {
	userIDValue, exists := c.Get("userID")
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
		return
	}

	userID, _ := userIDValue.(string)

	var user models.User
	if err := config.DB.Where("id = ?", userID).First(&user).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "user not found"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"user": userToResponse(user),
	})
}
