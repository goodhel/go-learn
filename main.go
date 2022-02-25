package main

import (
	"database/sql"
	"go-privy/pkg/database"
	"go-privy/pkg/routes"
	"log"
	"time"

	_ "github.com/go-sql-driver/mysql"
)

func main() {
	var err error

	database.DB, err = sql.Open("mysql", database.DbURL(database.BuildDBConfig()))

	if err != nil {
		log.Fatal(err)
	}
	// Setting Connecetion Pooling
	database.DB.SetConnMaxLifetime(time.Minute * 3)
	database.DB.SetMaxOpenConns(10)
	database.DB.SetMaxIdleConns(10)

	defer database.DB.Close()

	router := routes.Routes()

	router.Run("localhost:8080")
}
