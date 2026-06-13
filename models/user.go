package models

import (
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"
)

type User struct {
	ID           uuid.UUID `json:"id" gorm:"primaryKey"`
	Email        string    `json:"email" gorm:"unique;not null"`
	PasswordHash string    `json:"-" gorm:"not null"`
	RefreshToken string    `json:"-"`
	ResetToken   string    `json:"-"`
	ResetExpires time.Time `json:"-"`
	CreatedAt    time.Time
	UpdatedAt    time.Time
	DeletedAt    gorm.DeletedAt
}

func (u *User) BeforeCreate(tx *gorm.DB) (err error) {

	if u.ID == uuid.Nil {
		u.ID = uuid.New()
	}
	return nil
}
