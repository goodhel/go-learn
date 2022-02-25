package saldo

import (
	"database/sql"
	"errors"
	"fmt"
	"go-privy/pkg/database"
	"go-privy/pkg/jwt"
	"net/http"

	"github.com/gin-gonic/gin"
)

type Saldo struct {
	Nominal int64 `json:"nominal"`
}

type CheckUserBalance struct {
	ID      uint64 `json:"id"`
	UserId  int64  `json:"user_id"`
	Balance int64  `json:"balance"`
}

type TransferSaldo struct {
	Nominal int64  `json:"nominal"`
	To      uint64 `json:"to"`
}

type Response struct {
	Status bool
	Code   int
	Data   string
	Error  string
}

func SelfAddSaldo(c *gin.Context) {
	var body *Saldo

	// Bind Json into Saldo
	if err := c.BindJSON(&body); err != nil {
		c.JSON(http.StatusUnprocessableEntity, gin.H{"error": "Invalid json provided"})
		return
	}

	tokenAuth, err := jwt.ExtracTokenMetadata(c.Request)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized"})
		return
	}

	userId := tokenAuth.UserId
	saldo, err := AddSaldo(userId, body, &gin.Context{})

	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Add saldo successfully", "data": saldo})
}

func SelfTransfer(c *gin.Context) {
	var body TransferSaldo
	saldo := &Saldo{}

	// Bind Json into TransferSaldo
	if err := c.BindJSON(&body); err != nil {
		c.JSON(http.StatusUnprocessableEntity, gin.H{"error": "Invalid json provided"})
		return
	}

	tokenAuth, err := jwt.ExtracTokenMetadata(c.Request)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized"})
		return
	}

	userId := tokenAuth.UserId

	saldo.Nominal = body.Nominal

	sub, err := SubSaldo(userId, saldo, &gin.Context{})
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	add, err := AddSaldo(body.To, saldo, &gin.Context{})
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	tf := map[string]int64{
		"sub": sub,
		"add": add,
	}

	c.JSON(http.StatusOK, gin.H{"message": "Transfer saldo successfully", "data": tf})
}

func AddSaldo(userId uint64, body *Saldo, c *gin.Context) (int64, error) {
	var sal CheckUserBalance

	err2 := database.DB.QueryRow("SELECT id, userId, balance FROM user_balance WHERE userId = ?", userId).Scan(&sal.ID, &sal.UserId, &sal.Balance)

	// Check User have balance or not
	if err2 != nil && err2 == sql.ErrNoRows {
		// Insert new balance
		result, err := database.DB.Exec("INSERT INTO user_balance (userId, balance, balanceAchieve) VALUES (?,?,?)",
			userId, body.Nominal, body.Nominal)

		if err != nil {
			return 0, err
		}

		// Get the last id inserted
		id, err := result.LastInsertId()
		if err != nil {
			err := errors.New("error get last id")
			return 0, err
		}

		// Insert History Balance
		resultHis, errHis := database.DB.Exec(`INSERT INTO user_balance_history (userBalanceId, balanceBefore, balanceAfter,
			activity, type, ip, location, userAgent, author) VALUES (?,?,?,?,?,?,?,?,?)`,
			id, 0, body.Nominal, "Kredit saldo", "kredit", "127.0.0.1", "Unknown", "Postman", userId)
		if errHis != nil {
			return 0, err
		}

		fmt.Print(resultHis)

		return id, nil
	} else if err2 != nil {
		err := errors.New("user balance not found")
		return 0, err
	}

	var newBalance = sal.Balance + body.Nominal

	// Update Balance
	result, err := database.DB.Exec(`UPDATE user_balance SET balance = ?, balanceAchieve = ? WHERE id = ?`, newBalance, newBalance, sal.ID)
	if err != nil {
		return 0, err
	}

	// Insert History Balance
	resultHis, errHis := database.DB.Exec(`INSERT INTO user_balance_history (userBalanceId, balanceBefore, balanceAfter,
		activity, type, ip, location, userAgent, author) VALUES (?,?,?,?,?,?,?,?,?)`,
		sal.ID, sal.Balance, newBalance, "Kredit saldo", "kredit", "127.0.0.1", "Unknown", "Postman", userId)
	if errHis != nil {
		return 0, errHis
	}

	fmt.Print(resultHis)

	affectedRows, err := result.RowsAffected()

	if err != nil {
		return 0, err
	}

	return affectedRows, nil
}

func SubSaldo(userId uint64, body *Saldo, c *gin.Context) (int64, error) {
	var sal CheckUserBalance

	err2 := database.DB.QueryRow("SELECT id, userId, balance FROM user_balance WHERE userId = ?", userId).Scan(&sal.ID, &sal.UserId, &sal.Balance)

	if err2 != nil {
		err := errors.New("user balance not found, please add user balance first")
		return 0, err
	}

	if sal.Balance < body.Nominal {
		err := errors.New("your balance not enough")
		return 0, err
	}

	var newBalance = sal.Balance - body.Nominal

	// Update Balance
	result, err := database.DB.Exec(`UPDATE user_balance SET balance = ?, balanceAchieve = ? WHERE id = ?`, newBalance, newBalance, sal.ID)
	if err != nil {
		return 0, err
	}

	// Insert History Balance
	resultHis, errHis := database.DB.Exec(`INSERT INTO user_balance_history (userBalanceId, balanceBefore, balanceAfter,
		activity, type, ip, location, userAgent, author) VALUES (?,?,?,?,?,?,?,?,?)`,
		sal.ID, sal.Balance, newBalance, "Debit saldo", "debit", "127.0.0.1", "Unknown", "Postman", userId)
	if errHis != nil {
		return 0, err
	}

	fmt.Print(resultHis)

	affectedRows, err := result.RowsAffected()

	if err != nil {
		return 0, err
	}

	return affectedRows, nil
}
