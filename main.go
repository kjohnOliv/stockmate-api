package main

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/joho/godotenv"
	"golang.org/x/crypto/bcrypt"
)

// --- MODELS ---

type User struct {
	ID            int    `json:"id"`
	Username      string `json:"username"`
	FullName      string `json:"full_name"`
	Email         string `json:"email"`
	Password      string `json:"password,omitempty"`
	Role          string `json:"role"`
	ContactNumber string `json:"contact_number"`
	IsActive      bool   `json:"is_active"`
	Status        string `json:"status"`
}

type Ingredient struct {
	ID        int     `json:"id"`
	Item      string  `json:"item"`
	Category  string  `json:"category"`
	Qty       float64 `json:"qty"`
	Threshold float64 `json:"threshold"`
	Unit      string  `json:"unit"`
	Price     float64 `json:"price"`
	Status    string  `json:"status"`
}

type RecipeIngredient struct {
	InventoryID int     `json:"inventoryId"`
	ItemName    string  `json:"itemName"`
	Qty         float64 `json:"qty"`
	Unit        string  `json:"unit"`
}

type Recipe struct {
	ID          int                `json:"id"`
	Name        string             `json:"name"`
	Category    string             `json:"category"`
	Allergens   string             `json:"allergens"`
	PaxSize     int                `json:"pax_size"`
	Price       float64            `json:"price"`
	Ingredients []RecipeIngredient `json:"ingredients"`
}

type MealPlan struct {
	ID       int             `json:"id"`
	DateFrom string          `json:"date_from"`
	DateTo   string          `json:"date_to"`
	Status   string          `json:"status"`
	PlanData json.RawMessage `json:"plan_data"`
}

type MealPlanDay struct {
	Date  string        `json:"date"`
	Meals MealPlanMeals `json:"meals"`
}

type MealPlanMeals struct {
	Breakfast []MealItem `json:"breakfast"`
	Lunch     []MealItem `json:"lunch"`
	Snack     []MealItem `json:"snack"`
}

type MealItem struct {
	Name string `json:"name"`
	Pax  int    `json:"pax"`
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

// --- GLOBALS ---

var db *pgxpool.Pool
var otpStore = make(map[string]string)
var otpVerifiedStore = make(map[string]bool)
var otpLock sync.RWMutex
var rateLimitStore = make(map[string]time.Time) // IP -> last OTP request time
var rateLimitLock sync.RWMutex

// --- DATABASE MIGRATIONS ---

func runMigrations() {
	// 1. Create Table
	query := `CREATE TABLE IF NOT EXISTS users (
        id SERIAL PRIMARY KEY,
        username VARCHAR(100) UNIQUE NOT NULL,
        full_name VARCHAR(255),
        email VARCHAR(255) UNIQUE NOT NULL,
        password VARCHAR(255) NOT NULL,
        role VARCHAR(50) DEFAULT 'staff',
        is_active BOOLEAN DEFAULT false,
        status VARCHAR(50) DEFAULT 'pending',
        contact_number VARCHAR(20)
    );`
	_, err := db.Exec(context.Background(), query)
	if err != nil {
		fmt.Println("❌ Migration error:", err)
	}

	fmt.Println("✅ Running migrations & seeding admin...")
	if err := ensureAdminAccount(); err != nil {
		fmt.Println("❌ Seed error:", err)
	} else {
		fmt.Println("✅ Admin user (Hashed) ensured/created")
	}
}

func runAppMigrations() error {
	statements := []string{
		`CREATE TABLE IF NOT EXISTS users (
			id SERIAL PRIMARY KEY,
			username VARCHAR(100) UNIQUE NOT NULL,
			full_name VARCHAR(255),
			email VARCHAR(255) UNIQUE NOT NULL,
			password VARCHAR(255) NOT NULL,
			role VARCHAR(50) DEFAULT 'staff',
			is_active BOOLEAN DEFAULT false,
			status VARCHAR(50) DEFAULT 'pending',
			contact_number VARCHAR(20)
		)`,
		`CREATE TABLE IF NOT EXISTS inventory (
			id SERIAL PRIMARY KEY,
			item VARCHAR(255) NOT NULL,
			category VARCHAR(100),
			qty DOUBLE PRECISION DEFAULT 0,
			threshold DOUBLE PRECISION DEFAULT 0,
			unit VARCHAR(50),
			price DOUBLE PRECISION DEFAULT 0,
			status VARCHAR(50) DEFAULT 'In Stock'
		)`,
		`ALTER TABLE inventory ADD CONSTRAINT inventory_item_unique UNIQUE (item)`,
		`CREATE TABLE IF NOT EXISTS recipes (
			id SERIAL PRIMARY KEY,
			name VARCHAR(255) NOT NULL,
			category VARCHAR(100),
			allergens TEXT,
			pax_size INT DEFAULT 1,
			price DOUBLE PRECISION DEFAULT 0
		)`,
		`CREATE TABLE IF NOT EXISTS recipe_ingredients (
			id SERIAL PRIMARY KEY,
			recipe_id INT REFERENCES recipes(id) ON DELETE CASCADE,
			inventory_id INT REFERENCES inventory(id) ON DELETE CASCADE,
			qty DOUBLE PRECISION NOT NULL DEFAULT 0
		)`,
		`CREATE TABLE IF NOT EXISTS meal_plans (
			id SERIAL PRIMARY KEY,
			date_from DATE NOT NULL,
			date_to DATE NOT NULL,
			status VARCHAR(20) NOT NULL DEFAULT 'draft',
			plan_data JSONB NOT NULL DEFAULT '[]'::jsonb
		)`,
		`ALTER TABLE users ADD COLUMN IF NOT EXISTS full_name VARCHAR(255)`,
		`ALTER TABLE users ADD COLUMN IF NOT EXISTS role VARCHAR(50) DEFAULT 'staff'`,
		`ALTER TABLE users ADD COLUMN IF NOT EXISTS is_active BOOLEAN DEFAULT false`,
		`ALTER TABLE users ADD COLUMN IF NOT EXISTS status VARCHAR(50) DEFAULT 'pending'`,
		`ALTER TABLE users ADD COLUMN IF NOT EXISTS contact_number VARCHAR(20)`,
	}

	for _, stmt := range statements {
		if _, err := db.Exec(context.Background(), stmt); err != nil {
			// PostgreSQL raises duplicate_object when the named constraint already exists.
			if strings.Contains(strings.ToLower(err.Error()), "already exists") {
				continue
			}
			return err
		}
	}

	if err := seedInventory(); err != nil {
		return err
	}

	return ensureAdminAccount()
}

func seedInventory() error {
	seed := []Ingredient{
		{Item: "Bell Pepper", Category: "Vegetable", Qty: 1, Threshold: 5, Unit: "PCS", Price: 25},
		{Item: "Carrots", Category: "Vegetable", Qty: 25, Threshold: 10, Unit: "PCS", Price: 85},
		{Item: "Chicken", Category: "Meat", Qty: 25, Threshold: 5, Unit: "KG", Price: 185},
		{Item: "Pork", Category: "Meat", Qty: 25, Threshold: 5, Unit: "KG", Price: 225},
	}

	for _, i := range seed {
		i.Status = calculateStatus(i.Qty, i.Threshold)
		if _, err := db.Exec(
			context.Background(),
			`INSERT INTO inventory (item, category, qty, threshold, unit, price, status)
			VALUES ($1,$2,$3,$4,$5,$6,$7)
			ON CONFLICT (item) DO UPDATE
			SET category = EXCLUDED.category,
			    qty = EXCLUDED.qty,
			    threshold = EXCLUDED.threshold,
			    unit = EXCLUDED.unit,
			    price = EXCLUDED.price,
			    status = EXCLUDED.status`,
			i.Item, i.Category, i.Qty, i.Threshold, i.Unit, i.Price, i.Status,
		); err != nil {
			return err
		}
	}

	return nil
}

func normalizeLoginIdentifier(email, username, identifier string) string {
	for _, value := range []string{email, username, identifier} {
		if clean := strings.ToLower(strings.TrimSpace(value)); clean != "" {
			return clean
		}
	}
	return ""
}

func ensureAdminAccount() error {
	// Get admin credentials from environment
	adminEmail := strings.ToLower(strings.TrimSpace(os.Getenv("ADMIN_EMAIL")))
	adminPassword := os.Getenv("ADMIN_PASSWORD")

	if adminEmail == "" || adminPassword == "" {
		// Keep the legacy admin account working when env vars are not set.
		adminEmail = "devillakelvinjohn@gmail.com"
		adminPassword = "admin123"
	}

	hashedAdmin, err := bcrypt.GenerateFromPassword([]byte(adminPassword), bcrypt.DefaultCost)
	if err != nil {
		return err
	}

	updateQuery := `UPDATE users
		SET username = 'admin',
		    full_name = 'Kelvin John De Villa',
		    email = $1,
		    password = $2,
		    role = 'admin',
		    is_active = true,
		    status = 'approved',
		    contact_number = '09123456789'
		WHERE LOWER(TRIM(email)) = $1 OR LOWER(TRIM(username)) = 'admin'`

	tag, err := db.Exec(context.Background(), updateQuery, adminEmail, string(hashedAdmin))
	if err != nil {
		return err
	}

	if tag.RowsAffected() > 0 {
		return nil
	}

	insertQuery := `INSERT INTO users (username, full_name, email, password, role, is_active, status, contact_number)
		VALUES ('admin', 'Kelvin John De Villa', $1, $2, 'admin', true, 'approved', '09123456789')`

	_, err = db.Exec(context.Background(), insertQuery, adminEmail, string(hashedAdmin))
	return err
}

func verifyPassword(storedPassword, inputPassword string) error {
	storedPassword = strings.TrimSpace(storedPassword)
	inputPassword = strings.TrimSpace(inputPassword)

	if storedPassword == "" || inputPassword == "" {
		return errors.New("empty password")
	}

	// Always use bcrypt for hashed passwords (starts with $2a$, $2b$, or $2y$)
	if strings.HasPrefix(storedPassword, "$2") {
		return bcrypt.CompareHashAndPassword([]byte(storedPassword), []byte(inputPassword))
	}

	// Fallback for plain text passwords (legacy - should not happen in production)
	if storedPassword == inputPassword {
		return nil
	}

	return bcrypt.ErrMismatchedHashAndPassword
}

func isColumnMissingError(err error) bool {
	if err == nil {
		return false
	}
	errMsg := strings.ToLower(err.Error())
	return strings.Contains(errMsg, "column") && strings.Contains(errMsg, "does not exist")
}

func repairUsersSchema() error {
	statements := []string{
		`ALTER TABLE users ADD COLUMN IF NOT EXISTS full_name VARCHAR(255)`,
		`ALTER TABLE users ADD COLUMN IF NOT EXISTS role VARCHAR(50) DEFAULT 'staff'`,
		`ALTER TABLE users ADD COLUMN IF NOT EXISTS is_active BOOLEAN DEFAULT false`,
		`ALTER TABLE users ADD COLUMN IF NOT EXISTS status VARCHAR(50) DEFAULT 'pending'`,
		`ALTER TABLE users ADD COLUMN IF NOT EXISTS contact_number VARCHAR(20)`,
	}

	for _, stmt := range statements {
		if _, err := db.Exec(context.Background(), stmt); err != nil {
			return err
		}
	}

	return nil
}

// --- HELPERS ---

func sendJSON(c *gin.Context, code int, data interface{}) {
	c.JSON(code, APIResponse{Success: true, Data: data})
}

func sendError(c *gin.Context, code int, msg string, err error) {
	errMsg := ""
	if err != nil {
		errMsg = err.Error()
	}
	c.JSON(code, ErrorModel{Success: false, Code: code, Message: msg, Error: errMsg})
}

func calculateStatus(qty, threshold float64) string {
	if qty <= 0 {
		return "Out of Stock"
	}
	if qty <= threshold {
		return "Low Stock"
	}
	return "In Stock"
}

// generateOTP creates a cryptographically secure 6-digit OTP
func generateOTP() string {
	max := big.NewInt(1000000)
	randomNum, err := rand.Int(rand.Reader, max)
	if err != nil {
		return "000000" // Fallback
	}
	return fmt.Sprintf("%06d", randomNum)
}

func sendEmail(to, subject, body string) {
	fmt.Printf("📧 Email simulation: To: %s | Subject: %s | Message: %s\n", to, subject, body)
}

// --- MAIN ---

func main() {
	godotenv.Load()
	dbURL := os.Getenv("DATABASE_URL")
	var err error
	db, err = pgxpool.New(context.Background(), dbURL)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Unable to connect to database: %v\n", err)
		os.Exit(1)
	}
	defer db.Close()

	if err := runAppMigrations(); err != nil {
		fmt.Fprintf(os.Stderr, "Unable to run migrations: %v\n", err)
		os.Exit(1)
	}
	if err := repairUsersSchema(); err != nil {
		fmt.Fprintf(os.Stderr, "Unable to repair users schema: %v\n", err)
		os.Exit(1)
	}

	r := gin.Default()
	if err := r.SetTrustedProxies([]string{"127.0.0.1", "::1"}); err != nil {
		fmt.Fprintf(os.Stderr, "Unable to set trusted proxies: %v\n", err)
		os.Exit(1)
	}

	// Setup CORS with environment-based origins
	allowedOrigins := []string{"http://localhost:3000", "http://127.0.0.1:3000"}
	if customOrigins := os.Getenv("ALLOWED_ORIGINS"); customOrigins != "" {
		allowedOrigins = strings.Split(customOrigins, ",")
	}

	r.Use(cors.New(cors.Config{
		AllowOrigins:     allowedOrigins,
		AllowMethods:     []string{"GET", "POST", "PATCH", "DELETE", "PUT", "OPTIONS"},
		AllowHeaders:     []string{"Origin", "Content-Type", "Accept", "Authorization"},
		AllowCredentials: true,
		MaxAge:           12 * time.Hour,
	}))

	r.Static("/style", "./style")
	r.Static("/images", "./images")
	r.Static("/js", "./js")
	r.StaticFile("/", "./views/index.html")

	r.NoRoute(func(c *gin.Context) {
		sendError(c, 404, "Route not found", nil)
	})

	r.NoMethod(func(c *gin.Context) {
		sendError(c, 405, "Method not allowed", nil)
	})

	r.GET("/health", func(c *gin.Context) {
		c.JSON(200, gin.H{"success": true, "message": "OK"})
	})

	// --- ROUTES ---
	auth := r.Group("/auth")
	{
		auth.POST("/login", handleLogin)
		auth.POST("/register", handleRegister)
		auth.POST("/forgot-password", handleForgotPassword)
		auth.POST("/verify-otp", handleVerifyOTP)
		auth.POST("/change-password", handleChangePassword)
		auth.POST("/logout", handleLogout)
	}

	inventory := r.Group("/inventory")
	{
		inventory.GET("/", handleGetInventory)
		inventory.POST("/", handleAddIngredient)
		inventory.PUT("/:id", handleUpdateIngredient)
		inventory.DELETE("/:id", handleDeleteIngredient)
	}

	dashboard := r.Group("/dashboard")
	{
		dashboard.GET("/overview", handleGetDashboardOverview)
		dashboard.GET("/analytics", handleGetDashboardAnalytics)
	}

	recipes := r.Group("/recipes")
	{
		recipes.GET("/", handleGetRecipes)
		recipes.POST("/", handleSaveRecipe)
		recipes.PUT("/:id", handleUpdateRecipe)
		recipes.DELETE("/:id", handleDeleteRecipe)
	}

	mealplans := r.Group("/mealplans")
	{
		mealplans.GET("/", handleGetMealPlans)
		mealplans.GET("/:id", handleGetMealPlanByID)
		mealplans.POST("/", handleSaveMealPlan)
		mealplans.PATCH("/:id/status", handleUpdateMealPlanStatus)
		mealplans.DELETE("/:id", handleDeleteMealPlan)
		mealplans.GET("/active/menu", handleGetActiveMenuForStudents)
		mealplans.GET("/active/ingredients", handleGetActivePlanIngredients)
	}

	users := r.Group("/users")
	{
		users.GET("/", handleGetAccounts)
		users.GET("/pending", handleGetPendingAccounts)
		users.GET("/profile/:id", handleGetProfile)
		users.PUT("/profile/:id", handleUpdateProfile)
		users.PATCH("/status/:id", handleToggleStatus)
		users.GET("/pending-count", handleGetPendingCount)
		users.DELETE("/:id", handleDeleteUser)
	}

	// Protected API routes (require authentication)
	api := r.Group("/api", authMiddleware)
	{
		api.GET("/health", func(c *gin.Context) {
			c.JSON(200, gin.H{"success": true, "message": "OK"})
		})
		api.GET("/dashboard/overview", handleGetDashboardOverview)
		api.GET("/dashboard/analytics", handleGetDashboardAnalytics)

		api.GET("/inventory", handleGetInventory)
		api.POST("/inventory", handleAddIngredient)
		api.PUT("/inventory/:id", handleUpdateIngredient)
		api.DELETE("/inventory/:id", handleDeleteIngredient)

		api.GET("/recipes", handleGetRecipes)
		api.POST("/recipes", handleSaveRecipe)
		api.PUT("/recipes/:id", handleUpdateRecipe)
		api.DELETE("/recipes/:id", handleDeleteRecipe)

		api.GET("/meal-plans", handleGetMealPlans)
		api.GET("/meal-plans/:id", handleGetMealPlanByID)
		api.POST("/meal-plans", handleSaveMealPlan)
		api.PATCH("/meal-plans/:id/status", handleUpdateMealPlanStatus)
		api.DELETE("/meal-plans/:id", handleDeleteMealPlan)
		api.GET("/meal-plans/active", handleGetActiveMenuForStudents)
		api.GET("/meal-plans/active/ingredients", handleGetActivePlanIngredients)

		api.GET("/profile/:id", handleGetProfile)
		api.PUT("/profile/:id", handleUpdateProfile)
		api.GET("/users/profile/:id", handleGetProfile)
		api.PUT("/users/profile/:id", handleUpdateProfile)
		api.GET("/users/pending", handleGetPendingAccounts)
		api.GET("/users", handleGetAccounts)
		api.DELETE("/users/:id", handleDeleteUser)
		api.PATCH("/users/:id/status", handleToggleStatus)
	}

	// Legacy routes for backward compatibility
	r.GET("/profile/:id", handleGetProfile)
	r.PUT("/profile/:id", handleUpdateProfile)

	port := strings.TrimSpace(os.Getenv("PORT"))
	if port == "" {
		port = "8080"
	}
	if err := r.Run(":" + port); err != nil {
		fmt.Fprintf(os.Stderr, "Unable to start server: %v\n", err)
		os.Exit(1)
	}
}

// authMiddleware verifies that the user is authenticated
func authMiddleware(c *gin.Context) {
	authorizationHeader := c.GetHeader("Authorization")
	if authorizationHeader == "" {
		c.JSON(401, gin.H{"success": false, "message": "Missing authorization header"})
		c.Abort()
		return
	}
	// For now, we just check if header exists. In production,
	// you'd validate the JWT token here
	c.Next()
}

// --- AUTH HANDLERS ---

func handleLogin(c *gin.Context) {
	var req struct {
		Email      string `json:"email"`
		Username   string `json:"username"`
		Identifier string `json:"identifier"`
		Password   string `json:"password"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(400, gin.H{"success": false, "message": "Invalid request format"})
		return
	}

	var u User
	var dbPassword string
	loginID := normalizeLoginIdentifier(req.Email, req.Username, req.Identifier)
	if loginID == "" {
		c.JSON(400, gin.H{"success": false, "message": "Email or username is required"})
		return
	}

	query := `
        SELECT id, username, COALESCE(full_name,''), email, password, role, is_active, status, COALESCE(contact_number, '') 
        FROM users
        WHERE LOWER(TRIM(email)) = $1 OR LOWER(TRIM(username)) = $1`

	err := db.QueryRow(context.Background(), query, loginID).Scan(
		&u.ID, &u.Username, &u.FullName, &u.Email, &dbPassword, &u.Role, &u.IsActive, &u.Status, &u.ContactNumber,
	)

	if err != nil {
		if isColumnMissingError(err) {
			if repairErr := repairUsersSchema(); repairErr == nil {
				err = db.QueryRow(context.Background(), query, loginID).Scan(
					&u.ID, &u.Username, &u.FullName, &u.Email, &dbPassword, &u.Role, &u.IsActive, &u.Status, &u.ContactNumber,
				)
			}
		}
	}

	if err != nil {
		if !errors.Is(err, pgx.ErrNoRows) {
			fmt.Println("login query error:", err)
		}
		c.JSON(401, gin.H{"success": false, "message": "Invalid email or user not found"})
		return
	}

	if err := verifyPassword(dbPassword, req.Password); err != nil {
		c.JSON(401, gin.H{"success": false, "message": "Invalid password"})
		return
	}

	// Check if admin has approved
	if u.Status == "pending" {
		c.JSON(403, gin.H{"success": false, "message": "Awaiting admin approval."})
		return
	}

	c.JSON(200, gin.H{
		"success": true,
		"data": gin.H{
			"id": u.ID, "username": u.Username, "full_name": u.FullName, "email": u.Email,
			"role": u.Role, "status": u.Status, "is_active": u.IsActive, "contact_number": u.ContactNumber,
		},
	})
}

func handleRegister(c *gin.Context) {
	var req struct {
		Username string `json:"username"`
		FullName string `json:"full_name"`
		Email    string `json:"email"`
		Password string `json:"password"`
		Role     string `json:"role"`
		Contact  string `json:"contact_number"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		sendError(c, 400, "Invalid data", err)
		return
	}

	cleanEmail := strings.ToLower(strings.TrimSpace(req.Email))
	cleanUsername := strings.ToLower(strings.TrimSpace(req.Username))
	req.FullName = strings.TrimSpace(req.FullName)
	req.Contact = strings.TrimSpace(req.Contact)

	if cleanEmail == "" || cleanUsername == "" || strings.TrimSpace(req.Password) == "" {
		sendError(c, 400, "Username, email, and password are required", nil)
		return
	}

	if req.Role == "" {
		req.Role = "staff"
	}

	var emailExists bool
	if err := db.QueryRow(
		context.Background(),
		"SELECT EXISTS(SELECT 1 FROM users WHERE LOWER(TRIM(email)) = $1)",
		cleanEmail,
	).Scan(&emailExists); err != nil {
		sendError(c, 500, "Failed to validate email", err)
		return
	}

	var usernameExists bool
	if err := db.QueryRow(
		context.Background(),
		"SELECT EXISTS(SELECT 1 FROM users WHERE LOWER(TRIM(username)) = $1)",
		cleanUsername,
	).Scan(&usernameExists); err != nil {
		sendError(c, 500, "Failed to validate username", err)
		return
	}

	if emailExists && usernameExists {
		sendError(c, 409, "Email and username already registered", nil)
		return
	}
	if emailExists {
		sendError(c, 409, "Email already registered", nil)
		return
	}
	if usernameExists {
		sendError(c, 409, "Username already registered", nil)
		return
	}

	hashedPassword, _ := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)

	// Fixed Query: Matches 8 columns with 8 values
	query := `INSERT INTO users (username, full_name, email, password, role, is_active, status, contact_number)
          VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`

	_, err := db.Exec(context.Background(), query,
		cleanUsername, req.FullName, cleanEmail, string(hashedPassword), req.Role, false, "pending", req.Contact)

	if err != nil {
		sendError(c, 500, "Failed to register user", err)
		return
	}
	sendJSON(c, 201, "Registered successfully. Please wait for admin approval.")
}

// --- INVENTORY HANDLERS ---

func handleGetInventory(c *gin.Context) {
	rows, err := db.Query(context.Background(), "SELECT id, item, COALESCE(category,''), qty, threshold, unit, price, status FROM inventory ORDER BY item ASC")
	if err != nil {
		sendError(c, 500, "Database error", err)
		return
	}
	defer rows.Close()
	list := []Ingredient{}
	for rows.Next() {
		var i Ingredient
		if err := rows.Scan(&i.ID, &i.Item, &i.Category, &i.Qty, &i.Threshold, &i.Unit, &i.Price, &i.Status); err != nil {
			sendError(c, 500, "Failed to read inventory", err)
			return
		}
		list = append(list, i)
	}
	sendJSON(c, 200, list)
}

func handleAddIngredient(c *gin.Context) {
	var i Ingredient
	if err := c.ShouldBindJSON(&i); err != nil {
		sendError(c, 400, "Invalid input", err)
		return
	}
	i.Status = calculateStatus(i.Qty, i.Threshold)
	err := db.QueryRow(context.Background(), "INSERT INTO inventory (item, category, qty, threshold, unit, price, status) VALUES ($1,$2,$3,$4,$5,$6,$7) RETURNING id",
		i.Item, i.Category, i.Qty, i.Threshold, i.Unit, i.Price, i.Status).Scan(&i.ID)
	if err != nil {
		sendError(c, 500, "Insert failed", err)
		return
	}
	sendJSON(c, 201, i)
}

func handleUpdateIngredient(c *gin.Context) {
	id := c.Param("id")
	var i Ingredient
	if err := c.ShouldBindJSON(&i); err != nil {
		sendError(c, 400, "Invalid input", err)
		return
	}
	i.Status = calculateStatus(i.Qty, i.Threshold)
	_, err := db.Exec(context.Background(), "UPDATE inventory SET item=$1, category=$2, qty=$3, threshold=$4, unit=$5, price=$6, status=$7 WHERE id=$8",
		i.Item, i.Category, i.Qty, i.Threshold, i.Unit, i.Price, i.Status, id)
	if err != nil {
		sendError(c, 500, "Update failed", err)
		return
	}
	sendJSON(c, 200, "Updated")
}

func handleDeleteIngredient(c *gin.Context) {
	_, err := db.Exec(context.Background(), "DELETE FROM inventory WHERE id=$1", c.Param("id"))
	if err != nil {
		sendError(c, 500, "Delete failed", err)
		return
	}
	sendJSON(c, 200, "Deleted")
}

// --- DASHBOARD HANDLERS ---

func handleGetDashboardOverview(c *gin.Context) {
	var in, low, no int
	if err := db.QueryRow(context.Background(), "SELECT COUNT(*) FILTER (WHERE UPPER(status)='IN STOCK'), COUNT(*) FILTER (WHERE UPPER(status)='LOW STOCK'), COUNT(*) FILTER (WHERE UPPER(status)='OUT OF STOCK') FROM inventory").Scan(&in, &low, &no); err != nil {
		sendError(c, 500, "Failed to load dashboard overview", err)
		return
	}
	sendJSON(c, 200, gin.H{"inStock": in, "lowStock": low, "noStock": no})
}

func handleGetDashboardAnalytics(c *gin.Context) {
	rows, err := db.Query(context.Background(), "SELECT COALESCE(NULLIF(category,''),'Uncategorized'), COUNT(*) FROM inventory GROUP BY category")
	if err != nil {
		sendError(c, 500, "Failed to load dashboard analytics", err)
		return
	}
	defer rows.Close()
	dist := make(map[string]int)
	for rows.Next() {
		var cat string
		var count int
		if err := rows.Scan(&cat, &count); err != nil {
			sendError(c, 500, "Failed to read dashboard analytics", err)
			return
		}
		dist[cat] = count
	}
	sendJSON(c, 200, gin.H{"categoryDistribution": dist})
}

// --- RECIPE HANDLERS ---

func handleGetRecipes(c *gin.Context) {
	query := `SELECT r.id, r.name, r.category, r.allergens, r.pax_size, r.price, 
              COALESCE(json_agg(json_build_object('inventoryId', i.id, 'itemName', i.item, 'qty', ri.qty, 'unit', i.unit)) FILTER (WHERE ri.id IS NOT NULL), '[]')
              FROM recipes r LEFT JOIN recipe_ingredients ri ON r.id = ri.recipe_id LEFT JOIN inventory i ON ri.inventory_id = i.id
              GROUP BY r.id ORDER BY r.name ASC`
	rows, err := db.Query(context.Background(), query)
	if err != nil {
		sendError(c, 500, "Failed to load recipes", err)
		return
	}
	defer rows.Close()
	recipes := []Recipe{}
	for rows.Next() {
		var r Recipe
		var ingJSON []byte
		if err := rows.Scan(&r.ID, &r.Name, &r.Category, &r.Allergens, &r.PaxSize, &r.Price, &ingJSON); err != nil {
			sendError(c, 500, "Failed to read recipe", err)
			return
		}
		if err := json.Unmarshal(ingJSON, &r.Ingredients); err != nil {
			sendError(c, 500, "Failed to parse recipe ingredients", err)
			return
		}
		recipes = append(recipes, r)
	}
	sendJSON(c, 200, recipes)
}

func handleSaveRecipe(c *gin.Context) {
	var r Recipe
	if err := c.ShouldBindJSON(&r); err != nil {
		sendError(c, 400, "Invalid recipe payload", err)
		return
	}
	tx, err := db.Begin(context.Background())
	if err != nil {
		sendError(c, 500, "Failed to start transaction", err)
		return
	}
	defer tx.Rollback(context.Background())
	if err := tx.QueryRow(context.Background(), "INSERT INTO recipes (name, category, allergens, pax_size, price) VALUES ($1,$2,$3,$4,$5) RETURNING id",
		r.Name, r.Category, r.Allergens, r.PaxSize, r.Price).Scan(&r.ID); err != nil {
		sendError(c, 500, "Failed to save recipe", err)
		return
	}
	for _, ing := range r.Ingredients {
		if _, err := tx.Exec(context.Background(), "INSERT INTO recipe_ingredients (recipe_id, inventory_id, qty) VALUES ($1,$2,$3)", r.ID, ing.InventoryID, ing.Qty); err != nil {
			sendError(c, 500, "Failed to save recipe ingredients", err)
			return
		}
	}
	if err := tx.Commit(context.Background()); err != nil {
		sendError(c, 500, "Failed to commit recipe", err)
		return
	}
	sendJSON(c, 201, r)
}

func handleUpdateRecipe(c *gin.Context) {
	id := c.Param("id")
	var r Recipe
	if err := c.ShouldBindJSON(&r); err != nil {
		sendError(c, 400, "Invalid recipe payload", err)
		return
	}
	tx, err := db.Begin(context.Background())
	if err != nil {
		sendError(c, 500, "Failed to start transaction", err)
		return
	}
	defer tx.Rollback(context.Background())
	if _, err := tx.Exec(context.Background(), "UPDATE recipes SET name=$1, category=$2, allergens=$3, pax_size=$4, price=$5 WHERE id=$6", r.Name, r.Category, r.Allergens, r.PaxSize, r.Price, id); err != nil {
		sendError(c, 500, "Failed to update recipe", err)
		return
	}
	if _, err := tx.Exec(context.Background(), "DELETE FROM recipe_ingredients WHERE recipe_id=$1", id); err != nil {
		sendError(c, 500, "Failed to refresh recipe ingredients", err)
		return
	}
	for _, ing := range r.Ingredients {
		if _, err := tx.Exec(context.Background(), "INSERT INTO recipe_ingredients (recipe_id, inventory_id, qty) VALUES ($1,$2,$3)", id, ing.InventoryID, ing.Qty); err != nil {
			sendError(c, 500, "Failed to save recipe ingredients", err)
			return
		}
	}
	if err := tx.Commit(context.Background()); err != nil {
		sendError(c, 500, "Failed to commit recipe update", err)
		return
	}
	sendJSON(c, 200, "Updated")
}

func handleDeleteRecipe(c *gin.Context) {
	if _, err := db.Exec(context.Background(), "DELETE FROM recipes WHERE id=$1", c.Param("id")); err != nil {
		sendError(c, 500, "Failed to delete recipe", err)
		return
	}
	sendJSON(c, 200, "Deleted")
}

// --- MEAL PLAN HANDLERS ---

func handleGetMealPlans(c *gin.Context) {
	rows, err := db.Query(context.Background(), "SELECT id, date_from, date_to, status, plan_data FROM meal_plans ORDER BY id DESC")
	if err != nil {
		sendError(c, 500, "Failed to load meal plans", err)
		return
	}
	defer rows.Close()
	plans := []MealPlan{}
	for rows.Next() {
		var p MealPlan
		var df, dt time.Time
		if err := rows.Scan(&p.ID, &df, &dt, &p.Status, &p.PlanData); err != nil {
			sendError(c, 500, "Failed to read meal plan", err)
			return
		}
		p.DateFrom = df.Format("2006-01-02")
		p.DateTo = dt.Format("2006-01-02")
		plans = append(plans, p)
	}
	sendJSON(c, 200, plans)
}

func handleGetMealPlanByID(c *gin.Context) {
	var p MealPlan
	var df, dt time.Time
	if err := db.QueryRow(context.Background(), "SELECT id, date_from, date_to, status, plan_data FROM meal_plans WHERE id=$1", c.Param("id")).Scan(&p.ID, &df, &dt, &p.Status, &p.PlanData); err != nil {
		sendError(c, 404, "Meal plan not found", err)
		return
	}
	p.DateFrom = df.Format("2006-01-02")
	p.DateTo = dt.Format("2006-01-02")
	sendJSON(c, 200, p)
}

func handleSaveMealPlan(c *gin.Context) {
	var p MealPlan
	if err := c.ShouldBindJSON(&p); err != nil {
		sendError(c, 400, "Invalid meal plan payload", err)
		return
	}
	if err := db.QueryRow(context.Background(), "INSERT INTO meal_plans (date_from, date_to, status, plan_data) VALUES ($1,$2,$3,$4) RETURNING id",
		p.DateFrom, p.DateTo, strings.TrimSpace(p.Status), p.PlanData).Scan(&p.ID); err != nil {
		sendError(c, 500, "Failed to save meal plan", err)
		return
	}
	sendJSON(c, 201, p)
}

func handleUpdateMealPlanStatus(c *gin.Context) {
	var req struct {
		Status string `json:"status"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		sendError(c, 400, "Invalid status payload", err)
		return
	}
	if _, err := db.Exec(context.Background(), "UPDATE meal_plans SET status=$1 WHERE id=$2", req.Status, c.Param("id")); err != nil {
		sendError(c, 500, "Failed to update meal plan status", err)
		return
	}
	sendJSON(c, 200, "Updated")
}

func handleDeleteMealPlan(c *gin.Context) {
	if _, err := db.Exec(context.Background(), "DELETE FROM meal_plans WHERE id=$1", c.Param("id")); err != nil {
		sendError(c, 500, "Failed to delete meal plan", err)
		return
	}
	sendJSON(c, 200, "Deleted")
}

func handleGetActiveMenuForStudents(c *gin.Context) {
	var data json.RawMessage
	err := db.QueryRow(context.Background(), `
		SELECT plan_data
		FROM meal_plans
		WHERE LOWER(status) IN ('published', 'approved', 'ongoing')
		  AND CURRENT_DATE BETWEEN date_from AND date_to
		ORDER BY date_from DESC, id DESC
		LIMIT 1`).Scan(&data)
	if errors.Is(err, pgx.ErrNoRows) {
		sendJSON(c, 200, []interface{}{})
		return
	}
	if err != nil {
		sendError(c, 500, "Failed to load active meal plan", err)
		return
	}
	sendJSON(c, 200, data)
}

func handleGetActivePlanIngredients(c *gin.Context) {
	var planData []byte
	err := db.QueryRow(context.Background(), `
		SELECT plan_data
		FROM meal_plans
		WHERE LOWER(status) IN ('published', 'approved', 'ongoing')
		  AND CURRENT_DATE BETWEEN date_from AND date_to
		ORDER BY date_from DESC, id DESC
		LIMIT 1`).Scan(&planData)

	if err != nil || len(planData) == 0 {
		sendJSON(c, 200, []interface{}{})
		return
	}

	var days []MealPlanDay

	if err := json.Unmarshal(planData, &days); err != nil {
		sendError(c, 500, "Failed to parse meal plan JSON", err)
		return
	}

	type Total struct {
		Qty, Stocks float64
		Unit, Cat   string
	}
	totals := make(map[string]Total)

	for _, day := range days {
		all := [][]MealItem{
			day.Meals.Breakfast,
			day.Meals.Lunch,
			day.Meals.Snack,
		}

		for _, m := range all {
			for _, item := range m {
				rows, err := db.Query(context.Background(),
					`SELECT i.item, i.unit, i.category, i.qty, ri.qty, r.pax_size 
                     FROM recipes r 
                     JOIN recipe_ingredients ri ON r.id=ri.recipe_id 
                     JOIN inventory i ON ri.inventory_id=i.id 
                     WHERE r.name=$1`, item.Name)

				if err != nil {
					continue
				}

				for rows.Next() {
					var name, unit, cat string
					var currentStock, recipeQty float64
					var recipePaxSize int

					if err := rows.Scan(&name, &unit, &cat, &currentStock, &recipeQty, &recipePaxSize); err != nil {
						rows.Close()
						sendError(c, 500, "Failed to read active plan ingredients", err)
						return
					}

					if recipePaxSize > 0 {
						e := totals[name]
						e.Qty += recipeQty * (float64(item.Pax) / float64(recipePaxSize))
						e.Unit, e.Cat, e.Stocks = unit, cat, currentStock
						totals[name] = e
					}
				}
				rows.Close()
			}
		}
	}

	res := []gin.H{}
	for name, v := range totals {
		status := "pending"
		if v.Stocks >= v.Qty {
			status = "done"
		}
		res = append(res, gin.H{
			"item":     name,
			"est":      v.Qty,
			"unit":     v.Unit,
			"category": v.Cat,
			"stocks":   v.Stocks,
			"status":   status,
		})
	}
	sendJSON(c, 200, res)
}

// --- USER MANAGEMENT HANDLERS ---

func handleGetAccounts(c *gin.Context) {
	rows, err := db.Query(context.Background(), "SELECT id, username, COALESCE(full_name,''), email, role, COALESCE(contact_number,''), is_active, status FROM users ORDER BY id DESC")
	if err != nil {
		sendError(c, 500, "Failed to load users", err)
		return
	}
	defer rows.Close()
	users := []User{}
	for rows.Next() {
		var u User
		if err := rows.Scan(&u.ID, &u.Username, &u.FullName, &u.Email, &u.Role, &u.ContactNumber, &u.IsActive, &u.Status); err != nil {
			sendError(c, 500, "Failed to read users", err)
			return
		}
		users = append(users, u)
	}
	sendJSON(c, 200, users)
}

func handleGetPendingAccounts(c *gin.Context) {
	rows, err := db.Query(context.Background(), "SELECT id, username, COALESCE(full_name,''), email, role, COALESCE(contact_number,''), is_active, status FROM users WHERE LOWER(status) = 'pending' ORDER BY id DESC")
	if err != nil {
		sendError(c, 500, "Failed to load pending users", err)
		return
	}
	defer rows.Close()

	users := []User{}
	for rows.Next() {
		var u User
		if err := rows.Scan(&u.ID, &u.Username, &u.FullName, &u.Email, &u.Role, &u.ContactNumber, &u.IsActive, &u.Status); err != nil {
			sendError(c, 500, "Failed to read pending users", err)
			return
		}
		users = append(users, u)
	}

	sendJSON(c, 200, users)
}

func handleGetProfile(c *gin.Context) {
	var u User
	if err := db.QueryRow(context.Background(), "SELECT id, username, COALESCE(full_name,''), email, role, COALESCE(contact_number,'') FROM users WHERE id=$1", c.Param("id")).Scan(&u.ID, &u.Username, &u.FullName, &u.Email, &u.Role, &u.ContactNumber); err != nil {
		sendError(c, 404, "User not found", err)
		return
	}
	sendJSON(c, 200, u)
}

func handleUpdateProfile(c *gin.Context) {
	var req struct {
		FullName string `json:"full_name"`
		Contact  string `json:"contact_number"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		sendError(c, 400, "Invalid profile payload", err)
		return
	}
	if _, err := db.Exec(context.Background(), "UPDATE users SET full_name=$1, contact_number=$2 WHERE id=$3", req.FullName, req.Contact, c.Param("id")); err != nil {
		sendError(c, 500, "Failed to update profile", err)
		return
	}
	sendJSON(c, 200, "Updated")
}

func handleToggleStatus(c *gin.Context) {
	var req struct {
		Status   string `json:"status"`
		Role     string `json:"role"`
		IsActive bool   `json:"is_active"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		sendError(c, 400, "Invalid status payload", err)
		return
	}
	if _, err := db.Exec(context.Background(), "UPDATE users SET status=$1, role=COALESCE(NULLIF($2, ''), role), is_active=$3 WHERE id=$4", req.Status, req.Role, req.IsActive, c.Param("id")); err != nil {
		sendError(c, 500, "Failed to update user status", err)
		return
	}
	sendJSON(c, 200, "Updated")
}

func handleGetPendingCount(c *gin.Context) {
	var n int
	if err := db.QueryRow(context.Background(), "SELECT COUNT(*) FROM users WHERE status='pending'").Scan(&n); err != nil {
		sendError(c, 500, "Failed to load pending count", err)
		return
	}
	sendJSON(c, 200, n)
}

func handleDeleteUser(c *gin.Context) {
	if _, err := db.Exec(context.Background(), "DELETE FROM users WHERE id=$1", c.Param("id")); err != nil {
		sendError(c, 500, "Failed to delete user", err)
		return
	}
	sendJSON(c, 200, "Deleted")
}

func handleLogout(c *gin.Context) { sendJSON(c, 200, "Bye") }

// --- OTP / FORGOT PASSWORD ---

func handleForgotPassword(c *gin.Context) {
	var req struct {
		Email string `json:"email"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		sendError(c, 400, "Invalid request", err)
		return
	}
	cleanEmail := strings.ToLower(strings.TrimSpace(req.Email))
	if cleanEmail == "" {
		sendError(c, 400, "Email is required", nil)
		return
	}

	// Rate limiting: max 1 OTP request per 5 minutes per email
	rateLimitLock.Lock()
	lastRequest, exists := rateLimitStore[cleanEmail]
	now := time.Now()
	if exists && now.Sub(lastRequest) < 5*time.Minute {
		rateLimitLock.Unlock()
		sendError(c, 429, "Too many requests. Try again later", nil)
		return
	}
	rateLimitStore[cleanEmail] = now
	rateLimitLock.Unlock()

	var emailExists bool
	if err := db.QueryRow(context.Background(), "SELECT EXISTS(SELECT 1 FROM users WHERE LOWER(TRIM(email)) = $1)", cleanEmail).Scan(&emailExists); err != nil {
		sendError(c, 500, "Failed to verify email", err)
		return
	}
	if !emailExists {
		// Don't reveal if email exists or not for security
		sendJSON(c, 200, "If email exists, OTP was sent")
		return
	}

	otp := generateOTP()
	otpLock.Lock()
	otpStore[cleanEmail] = otp
	delete(otpVerifiedStore, cleanEmail)
	otpLock.Unlock()

	sendEmail(cleanEmail, "Password Reset", fmt.Sprintf("Reset code: %s (valid for 15 minutes)", otp))
	sendJSON(c, 200, "If email exists, OTP was sent")
}

func handleVerifyOTP(c *gin.Context) {
	var req struct {
		Email string `json:"email"`
		Code  string `json:"code"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		sendError(c, 400, "Invalid request", err)
		return
	}

	cleanEmail := strings.ToLower(strings.TrimSpace(req.Email))
	otpLock.RLock()
	val, ok := otpStore[cleanEmail]
	otpLock.RUnlock()

	if ok && val == strings.TrimSpace(req.Code) {
		otpLock.Lock()
		otpVerifiedStore[cleanEmail] = true
		otpLock.Unlock()
		sendJSON(c, 200, "Verified")
		return
	}
	sendError(c, 400, "Invalid or expired code", nil)
}

func handleChangePassword(c *gin.Context) {
	var req struct {
		Email    string `json:"email"`
		Password string `json:"password"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		sendError(c, 400, "Invalid request", err)
		return
	}

	cleanEmail := strings.ToLower(strings.TrimSpace(req.Email))
	if cleanEmail == "" || strings.TrimSpace(req.Password) == "" {
		sendError(c, 400, "Email and password are required", nil)
		return
	}

	// Validate password strength
	if len(strings.TrimSpace(req.Password)) < 8 {
		sendError(c, 400, "Password must be at least 8 characters long", nil)
		return
	}

	otpLock.RLock()
	verified := otpVerifiedStore[cleanEmail]
	otpLock.RUnlock()

	if !verified {
		sendError(c, 403, "OTP verification required", nil)
		return
	}

	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
	if err != nil {
		sendError(c, 500, "Failed to hash password", err)
		return
	}

	tag, err := db.Exec(context.Background(), "UPDATE users SET password = $1 WHERE LOWER(TRIM(email)) = $2", string(hashedPassword), cleanEmail)
	if err != nil {
		sendError(c, 500, "Failed to update password", err)
		return
	}
	if tag.RowsAffected() == 0 {
		sendError(c, 404, "Email not registered", nil)
		return
	}

	otpLock.Lock()
	delete(otpStore, cleanEmail)
	delete(otpVerifiedStore, cleanEmail)
	otpLock.Unlock()

	sendJSON(c, 200, "Password updated successfully")
}
