package auth

import (
	"fmt"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

var (
	jwtSecret []byte
	once      sync.Once
)

type Claims struct {
	UserID string `json:"user_id"`
	Type   string `json:"type"`
	jwt.RegisteredClaims
}

func Init(secret string) error {
	if secret == "" {
		return fmt.Errorf("SECRET_KEY is not configured")
	}
	once.Do(func() {
		jwtSecret = []byte(secret)
	})
	return nil
}

func GenerateToken(userID string) (string, string, error) {
	if len(jwtSecret) == 0 {
		return "", "", fmt.Errorf("jwt secret not configured")
	}

	now := time.Now()

	accessClaims := Claims{
		UserID: userID,
		Type:   "access",
		RegisteredClaims: jwt.RegisteredClaims{
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(15 * time.Minute)),
		},
	}

	accessToken := jwt.NewWithClaims(jwt.SigningMethodHS256, accessClaims)
	accessTokenString, err := accessToken.SignedString(jwtSecret)
	if err != nil {
		return "", "", err
	}

	refreshClaims := Claims{
		UserID: userID,
		Type:   "refresh",
		RegisteredClaims: jwt.RegisteredClaims{
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(7 * 24 * time.Hour)),
		},
	}

	refreshToken := jwt.NewWithClaims(jwt.SigningMethodHS256, refreshClaims)
	refreshTokenString, err := refreshToken.SignedString(jwtSecret)
	if err != nil {
		return "", "", err
	}

	return accessTokenString, refreshTokenString, nil
}

func ValidateToken(tokenString string, expectedType string) (*Claims, error) {
	if len(jwtSecret) == 0 {
		return nil, fmt.Errorf("jwt secret not configured")
	}

	claims := &Claims{}

	token, err := jwt.ParseWithClaims(
		tokenString,
		claims,
		func(token *jwt.Token) (any, error) {
			if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
				return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
			}
			return jwtSecret, nil
		},
	)

	if err != nil {
		return nil, err
	}

	if !token.Valid {
		return nil, fmt.Errorf("invalid token")
	}

	if claims.Type != expectedType {
		return nil, fmt.Errorf("expected %s token but got %s token", expectedType, claims.Type)
	}

	return claims, nil
}
