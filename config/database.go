package config

import (
	"Auth-gin-with-password-reset/models"
	"fmt"
	"log"
	"os"
	"sync"
	"time"

	"github.com/joho/godotenv"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
)

var (
	DB   *gorm.DB
	once sync.Once
)

func ConnectDB() error {
	var err error

	once.Do(func() {
		_ = godotenv.Load()

		host := os.Getenv("DB_HOST")
		port := os.Getenv("DB_PORT")
		user := os.Getenv("DB_USER")
		password := os.Getenv("DB_PASSWORD")
		dbName := os.Getenv("DB_NAME")
		sslMode := os.Getenv("DB_SSLMODE")

		if host == "" ||
			port == "" ||
			user == "" ||
			password == "" ||
			dbName == "" {
			err = fmt.Errorf("database environment variables missing")
			return
		}

		dsn := fmt.Sprintf(
			"host=%s user=%s password=%s dbname=%s port=%s sslmode=%s TimeZone=UTC",
			host,
			user,
			password,
			dbName,
			port,
			sslMode,
		)

		db, dbErr := gorm.Open(
			postgres.Open(dsn),
			&gorm.Config{},
		)

		if dbErr != nil {
			err = dbErr
			return
		}

		sqlDB, dbErr := db.DB()
		if dbErr != nil {
			err = dbErr
			return
		}

		sqlDB.SetMaxOpenConns(50)
		sqlDB.SetMaxIdleConns(25)
		sqlDB.SetConnMaxLifetime(5 * time.Minute)
		sqlDB.SetConnMaxIdleTime(2 * time.Minute)

		if dbErr := sqlDB.Ping(); dbErr != nil {
			err = dbErr
			return
		}

		if dbErr := db.AutoMigrate(
			&models.User{},
		); dbErr != nil {
			err = dbErr
			return
		}

		DB = db

		log.Println("PostgreSQL connected successfully")
	})

	return err
}
