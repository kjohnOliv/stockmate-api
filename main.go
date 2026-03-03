package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net/http"
	"net/smtp"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/joho/godotenv"
)

// --- MODELS ---

type User struct {
	ID            int    `json:"id"`
	Username      string `json:"username"`
	Email         string `json:"email"`
	Role          string `json:"role"`
	ContactNumber string `json:"contact_number"`
	IsActive      bool   `json:"is_active"`
}

type Ingredient struct {
	ID        int    `json:"id"`
	Item      string `json:"item"`
	Category  string `json:"category"`
	Qty       string `json:"qty"` // Must match ing.qty
	Threshold string `json:"threshold"`
	Unit      string `json:"unit"`
	Price     string `json:"price"`  // Must match ing.price
	Status    string `json:"status"` // Must match ing.status
}
type APIResponse struct {
	Success bool        `json:"success"`
	Data    interface{} `json:"data,omitempty"`
	Message string      `json:"message,omitempty"`
}

type ErrorModel struct {
	Success bool   `json:"success"`
	Code    int    `json:"code"`
	Message string `json:"message"`
	Error   string `json:"error,omitempty"`
}

var db *pgxpool.Pool

// --- HELPERS ---

func sendJSON(c *gin.Context, code int, data interface{}) {
	c.JSON(code, APIResponse{
		Success: true,
		Data:    data,
	})
}

func sendError(c *gin.Context, code int, msg string, err error) {
	errMsg := ""
	if err != nil {
		errMsg = err.Error()
	}
	c.JSON(code, ErrorModel{
		Success: false,
		Code:    code,
		Message: msg,
		Error:   errMsg,
	})
}

// FIXED: Ensures "No Stock" takes priority over "Low Stock"
func calculateStatus(qtyStr, thresholdStr string) string {
	cleanStr := func(s string) (int, bool) {
		var res string
		for _, r := range s {
			if r >= '0' && r <= '9' {
				res += string(r)
			}
		}
		if res == "" {
			return 0, false
		}
		val, _ := strconv.Atoi(res)
		return val, true
	}

	qty, qtyOk := cleanStr(qtyStr)
	threshold, thresholdOk := cleanStr(thresholdStr)

	if !qtyOk || !thresholdOk {
		return "Low Stock"
	}

	// CHECK QTY 0 FIRST
	if qty <= 0 {
		return "No Stock"
	}
	// THEN CHECK THRESHOLD
	if qty <= threshold {
		return "Low Stock"
	}
	return "In Stock"
}

func generateToken(n int) string {
	b := make([]byte, n)
	rand.Read(b)
	return hex.EncodeToString(b)
}

func sendEmail(to string, subject string, body string) error {
	from := os.Getenv("SMTP_USER")
	pass := os.Getenv("SMTP_PASS")
	host := os.Getenv("SMTP_HOST")
	port := os.Getenv("SMTP_PORT")
	msg := "From: " + from + "\n" + "To: " + to + "\n" + "Subject: " + subject + "\n" + "Mime-Version: 1.0;\n" + "Content-Type: text/html; charset=\"UTF-8\";\n\n" + body
	auth := smtp.PlainAuth("", from, pass, host)
	return smtp.SendMail(host+":"+port, auth, from, []string{to}, []byte(msg))
}

// --- MAIN ---

func main() {
	godotenv.Load()
	dbURL := os.Getenv("DATABASE_URL")
	if dbURL == "" {
		fmt.Println("❌ DATABASE_URL not found")
		os.Exit(1)
	}

	var err error
	db, err = pgxpool.New(context.Background(), dbURL)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Unable to connect to database: %v\n", err)
		os.Exit(1)
	}
	defer db.Close()

	r := gin.Default()
	r.Use(gin.Recovery())
	r.Use(cors.New(cors.Config{
		AllowOrigins:     []string{"http://localhost:3000"},
		AllowMethods:     []string{"GET", "POST", "PATCH", "DELETE", "PUT", "OPTIONS"},
		AllowHeaders:     []string{"Origin", "Content-Type", "Accept", "Authorization"},
		AllowCredentials: true,
		MaxAge:           12 * time.Hour,
	}))

	// --- ROUTES ---

	auth := r.Group("/auth")
	{
		auth.POST("/login", handleLogin)
		auth.POST("/logout", handleLogout)
		auth.POST("/register", handleRegister)
		auth.POST("/forgot-password", handleForgotPassword)
		auth.POST("/reset-password", handleResetPassword)
		auth.GET("/accounts", handleGetAccounts)
		auth.GET("/user/:id", handleGetProfile)
		auth.PATCH("/user/:id", handleUpdateProfile)
		auth.PATCH("/user/:id/status", handleToggleStatus)
	}

	api := r.Group("/api")
	{
		api.GET("/inventory", handleGetInventory)
		api.POST("/inventory", handleAddIngredient)
		api.PUT("/inventory/:id", handleUpdateIngredient)
		api.DELETE("/inventory/:id", handleDeleteIngredient)
	}

	fmt.Println("🚀 StockMate API running on http://localhost:8080")
	r.Run(":8080")
}

// --- AUTH & USER HANDLERS ---

func handleLogin(c *gin.Context) {
	var req struct {
		Email    string `json:"email"`
		Password string `json:"password"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		sendError(c, http.StatusBadRequest, "Invalid login data", err)
		return
	}
	var u User
	query := `SELECT id, username, email, role, COALESCE(contact_number, 'N/A'), is_active FROM users WHERE email=$1 AND password=$2`
	err := db.QueryRow(context.Background(), query, req.Email, req.Password).Scan(&u.ID, &u.Username, &u.Email, &u.Role, &u.ContactNumber, &u.IsActive)
	if err != nil {
		sendError(c, http.StatusUnauthorized, "Invalid email or password", err)
		return
	}
	if !u.IsActive {
		sendError(c, http.StatusForbidden, "Your account is currently Inactive.", nil)
		return
	}
	sendJSON(c, http.StatusOK, u)
}

func handleRegister(c *gin.Context) {
	var req struct {
		Username      string `json:"username" binding:"required"`
		Email         string `json:"email" binding:"required"`
		Password      string `json:"password" binding:"required"`
		Role          string `json:"role"`
		ContactNumber string `json:"contact_number"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		sendError(c, http.StatusBadRequest, "Invalid registration data", err)
		return
	}
	if req.Role == "" {
		req.Role = "Staff"
	}
	var userID int
	query := `INSERT INTO users (username, email, password, role, contact_number, is_active) VALUES ($1, $2, $3, $4, $5, false) RETURNING id`
	err := db.QueryRow(context.Background(), query, req.Username, req.Email, req.Password, req.Role, req.ContactNumber).Scan(&userID)
	if err != nil {
		sendError(c, http.StatusInternalServerError, "Registration failed", err)
		return
	}
	welcomeMsg := fmt.Sprintf("<h2>Welcome, %s!</h2><p>Account created as %s. Awaiting Admin activation.</p>", req.Username, req.Role)
	sendEmail(req.Email, "StockMate - Registration Successful", welcomeMsg)
	c.JSON(http.StatusCreated, APIResponse{Success: true, Message: "Registration successful!"})
}

func handleForgotPassword(c *gin.Context) {
	var req struct {
		Email string `json:"email" binding:"required"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		sendError(c, http.StatusBadRequest, "Email is required", err)
		return
	}
	resetToken := generateToken(3)
	query := `UPDATE users SET reset_token=$1 WHERE email=$2`
	result, err := db.Exec(context.Background(), query, resetToken, req.Email)
	if err != nil {
		sendError(c, http.StatusInternalServerError, "Database error", err)
		return
	}
	if result.RowsAffected() == 0 {
		sendError(c, http.StatusNotFound, "Email not found", nil)
		return
	}
	body := fmt.Sprintf("<h2>Password Reset</h2><p>Your reset code is: <strong>%s</strong></p>", resetToken)
	sendEmail(req.Email, "StockMate - Password Reset", body)
	sendJSON(c, http.StatusOK, "Reset code sent to email")
}

func handleResetPassword(c *gin.Context) {
	var req struct {
		Token    string `json:"token" binding:"required"`
		Password string `json:"password" binding:"required"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		sendError(c, http.StatusBadRequest, "Invalid data", err)
		return
	}
	query := `UPDATE users SET password=$1, reset_token=NULL WHERE reset_token=$2`
	result, err := db.Exec(context.Background(), query, req.Password, req.Token)
	if err != nil {
		sendError(c, http.StatusInternalServerError, "Failed to reset password", err)
		return
	}
	if result.RowsAffected() == 0 {
		sendError(c, http.StatusBadRequest, "Invalid or expired token", nil)
		return
	}
	sendJSON(c, http.StatusOK, "Password updated successfully")
}

func handleGetAccounts(c *gin.Context) {
	rows, err := db.Query(context.Background(), `SELECT id, username, email, role, COALESCE(contact_number, 'N/A'), is_active FROM users ORDER BY id ASC`)
	if err != nil {
		sendError(c, http.StatusInternalServerError, "Failed to fetch accounts", err)
		return
	}
	defer rows.Close()
	users := []User{}
	for rows.Next() {
		var u User
		rows.Scan(&u.ID, &u.Username, &u.Email, &u.Role, &u.ContactNumber, &u.IsActive)
		users = append(users, u)
	}
	sendJSON(c, http.StatusOK, users)
}

func handleToggleStatus(c *gin.Context) {
	id := c.Param("id")
	var req struct {
		IsActive bool `json:"is_active"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		sendError(c, http.StatusBadRequest, "Invalid status", err)
		return
	}
	_, err := db.Exec(context.Background(), `UPDATE users SET is_active=$1 WHERE id=$2`, req.IsActive, id)
	if err != nil {
		sendError(c, http.StatusInternalServerError, "Update failed", err)
		return
	}
	sendJSON(c, http.StatusOK, "User status updated")
}

func handleGetProfile(c *gin.Context) {
	id := c.Param("id")
	var u User
	query := `SELECT id, username, email, role, COALESCE(contact_number, 'N/A'), is_active FROM users WHERE id=$1`
	err := db.QueryRow(context.Background(), query, id).Scan(&u.ID, &u.Username, &u.Email, &u.Role, &u.ContactNumber, &u.IsActive)
	if err != nil {
		sendError(c, http.StatusNotFound, "User not found", err)
		return
	}
	sendJSON(c, http.StatusOK, u)
}

func handleUpdateProfile(c *gin.Context) {
	id := c.Param("id")
	var req struct {
		Username      string `json:"username"`
		ContactNumber string `json:"contact_number"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		sendError(c, http.StatusBadRequest, "Invalid data", err)
		return
	}
	_, err := db.Exec(context.Background(), `UPDATE users SET username=$1, contact_number=$2 WHERE id=$3`, req.Username, req.ContactNumber, id)
	if err != nil {
		sendError(c, http.StatusInternalServerError, "Update failed", err)
		return
	}
	sendJSON(c, http.StatusOK, "Profile updated")
}

// --- INVENTORY HANDLERS ---

func handleGetInventory(c *gin.Context) {
	// Explicitly using the singular "inventory" table
	rows, err := db.Query(context.Background(), `SELECT id, item, category, qty, threshold, unit, COALESCE(price, 'P0'), status FROM inventory ORDER BY id ASC`)
	if err != nil {
		sendError(c, http.StatusInternalServerError, "Failed to fetch inventory", err)
		return
	}
	defer rows.Close()
	inv := []Ingredient{}
	for rows.Next() {
		var i Ingredient
		rows.Scan(&i.ID, &i.Item, &i.Category, &i.Qty, &i.Threshold, &i.Unit, &i.Price, &i.Status)
		inv = append(inv, i)
	}
	sendJSON(c, http.StatusOK, inv)
}

func handleAddIngredient(c *gin.Context) {
	var i Ingredient
	if err := c.ShouldBindJSON(&i); err != nil {
		sendError(c, http.StatusBadRequest, "Invalid data format", err)
		return
	}

	i.Status = calculateStatus(i.Qty, i.Threshold)

	// IMPROVED: Ensure price always starts with one 'P' and has no extra spaces
	priceRaw := fmt.Sprintf("%v", i.Price)
	// Remove all existing 'P's and spaces, then add one 'P' back
	priceStr := strings.TrimSpace(strings.ReplaceAll(priceRaw, "P", ""))
	if priceStr == "" || priceStr == "<nil>" {
		priceStr = "0"
	}
	priceStr = "P" + priceStr

	query := `INSERT INTO inventory (item, category, qty, threshold, unit, price, status) VALUES ($1, $2, $3, $4, $5, $6, $7) RETURNING id`
	err := db.QueryRow(context.Background(), query, i.Item, i.Category, i.Qty, i.Threshold, i.Unit, priceStr, i.Status).Scan(&i.ID)
	if err != nil {
		sendError(c, http.StatusInternalServerError, "Save failed", err)
		return
	}
	sendJSON(c, http.StatusCreated, i)
}

func handleUpdateIngredient(c *gin.Context) {
	id := c.Param("id")
	var i Ingredient
	if err := c.ShouldBindJSON(&i); err != nil {
		sendError(c, http.StatusBadRequest, "Invalid data", err)
		return
	}

	i.Status = calculateStatus(i.Qty, i.Threshold)

	// Clean price formatting to prevent "PP 65"
	priceRaw := fmt.Sprintf("%v", i.Price)
	priceStr := strings.TrimSpace(strings.ReplaceAll(priceRaw, "P", ""))
	if priceStr == "" || priceStr == "<nil>" {
		priceStr = "0"
	}
	priceStr = "P" + priceStr

	query := `UPDATE inventory SET item=$1, category=$2, qty=$3, threshold=$4, unit=$5, price=$6, status=$7 WHERE id=$8`
	_, err := db.Exec(context.Background(), query, i.Item, i.Category, i.Qty, i.Threshold, i.Unit, priceStr, i.Status, id)
	if err != nil {
		sendError(c, http.StatusInternalServerError, "Update failed", err)
		return
	}
	sendJSON(c, http.StatusOK, "Updated successfully")
}

func handleDeleteIngredient(c *gin.Context) {
	id := c.Param("id")
	db.Exec(context.Background(), "DELETE FROM inventory WHERE id=$1", id)
	sendJSON(c, http.StatusOK, "Deleted")
}

func handleLogout(c *gin.Context) { sendJSON(c, http.StatusOK, "Logged out") }
