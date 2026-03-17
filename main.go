package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strconv"
	"time"

	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
	"github.com/jackc/pgx/v5/pgxpool" // Needed for pgxpool
	"github.com/joho/godotenv"        // Needed for godotenv
	"golang.org/x/crypto/bcrypt"      // Needed for bcrypt
	"gopkg.in/gomail.v2"              // Needed for gomail
)

// --- MODELS ---

type User struct {
	ID            int    `json:"id"`
	Username      string `json:"username"`
	FullName      string `json:"full_name"`
	Email         string `json:"email"`
	Password      string `json:"password"`
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

type Recipe struct {
	ID          int                `json:"id"`
	Name        string             `json:"name"`
	Category    string             `json:"category"`
	Allergens   string             `json:"allergens"`
	PaxSize     int                `json:"paxSize"`
	Price       float64            `json:"price"`
	Ingredients []RecipeIngredient `json:"ingredients"`
}

type RecipeIngredient struct {
	InventoryID int     `json:"inventoryId"`
	ItemName    string  `json:"itemName"`
	Unit        string  `json:"unit"`
	Qty         float64 `json:"qty"`
}

type MealPlan struct {
	ID       int             `json:"id"`
	DateFrom string          `json:"date_from"`
	DateTo   string          `json:"date_to"`
	Status   string          `json:"status"`
	PlanData json.RawMessage `json:"plan_data"`
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
		return "No Stock"
	}
	if qty <= threshold {
		return "Low Stock"
	}
	return "In Stock"
}

func sendEmail(to, subject, body string) error {
	m := gomail.NewMessage()
	m.SetHeader("From", os.Getenv("SMTP_EMAIL"))
	m.SetHeader("To", to)
	m.SetHeader("Subject", subject)
	m.SetBody("text/html", body)
	port, _ := strconv.Atoi(os.Getenv("SMTP_PORT"))
	d := gomail.NewDialer(os.Getenv("SMTP_HOST"), port, os.Getenv("SMTP_EMAIL"), os.Getenv("SMTP_PASS"))
	return d.DialAndSend(m)
}

// --- MAIN ---

func main() {
	godotenv.Load()
	dbURL := os.Getenv("DATABASE_URL")
	var err error
	db, err = pgxpool.New(context.Background(), dbURL)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Unable to connect: %v\n", err)
		os.Exit(1)
	}
	defer db.Close()

	r := gin.Default()
	r.Use(cors.New(cors.Config{
		AllowOrigins:     []string{"http://localhost:3000"},
		AllowMethods:     []string{"GET", "POST", "PATCH", "DELETE", "PUT", "OPTIONS"},
		AllowHeaders:     []string{"Origin", "Content-Type", "Accept", "Authorization"},
		AllowCredentials: true,
		MaxAge:           12 * time.Hour,
	}))

	auth := r.Group("/auth")
	{
		auth.POST("/login", handleLogin)
		auth.POST("/logout", handleLogout)
		auth.POST("/register", handleRegister)
		auth.GET("/accounts", handleGetAccounts)
		auth.GET("/pending-count", handleGetPendingCount)
		auth.PATCH("/user/:id/status", handleToggleStatus)
		auth.DELETE("/user/:id", handleDeleteUser)
		auth.GET("/user/:id", handleGetProfile)
		auth.PATCH("/user/:id", handleUpdateProfile)
		auth.POST("/forgot-password", handleForgotPassword)
		auth.POST("/verify-otp", handleVerifyOTP)
		auth.POST("/change-password", handleChangePassword)
	}

	api := r.Group("/api")
	{
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
		api.POST("/meal-plans", handleSaveMealPlan)
		api.PATCH("/meal-plans/:id/status", handleUpdateMealPlanStatus)
		api.GET("/meal-plans/active/ingredients", handleGetActivePlanIngredients)
		api.GET("/meal-plans/active", handleGetActiveMenuForStudents)
	}

	r.Run(":8080")
}

// --- AUTH HANDLERS ---

func handleLogin(c *gin.Context) {
	var req struct {
		Email    string `json:"email"`
		Password string `json:"password"`
	}
	c.ShouldBindJSON(&req)

	var u User
	var hashedPassword string

	// 1. Get user and their stored hash
	query := `SELECT id, username, COALESCE(full_name,''), email, password, role, is_active FROM users WHERE email = LOWER($1)`
	err := db.QueryRow(context.Background(), query, req.Email).Scan(&u.ID, &u.Username, &u.FullName, &u.Email, &hashedPassword, &u.Role, &u.IsActive)

	if err != nil {
		sendError(c, http.StatusUnauthorized, "User not found", nil)
		return
	}

	// 2. Compare the plain-text request password with the hashed database password
	err = bcrypt.CompareHashAndPassword([]byte(hashedPassword), []byte(req.Password))
	if err != nil {
		sendError(c, http.StatusUnauthorized, "Invalid password", nil)
		return
	}

	if !u.IsActive {
		sendError(c, http.StatusForbidden, "Account pending approval", nil)
		return
	}
	sendJSON(c, http.StatusOK, u)
}
func handleRegister(c *gin.Context) {
	var req struct {
		Username string `json:"username"`
		FullName string `json:"full_name"`
		Email    string `json:"email"`
		Role     string `json:"role"`
		Contact  string `json:"contact_number"`
	}
	c.ShouldBindJSON(&req)
	role := req.Role
	if role == "" {
		role = "staff"
	}
	tempPass := "changeme123"
	query := `INSERT INTO users (username, full_name, email, password, role, contact_number, is_active, status) 
              VALUES ($1, $2, LOWER($3), $4, $5, $6, false, 'pending')`
	_, err := db.Exec(context.Background(), query, req.Username, req.FullName, req.Email, tempPass, role, req.Contact)
	if err != nil {
		sendError(c, http.StatusInternalServerError, "Registration failed", err)
		return
	}
	sendJSON(c, http.StatusCreated, "Registered")
}

func handleGetAccounts(c *gin.Context) {
	query := `SELECT id, username, COALESCE(full_name,''), email, password, role, 
              COALESCE(contact_number,''), is_active, status 
              FROM users ORDER BY id DESC`
	rows, _ := db.Query(context.Background(), query)
	defer rows.Close()
	var users []User = []User{}
	for rows.Next() {
		var u User
		rows.Scan(&u.ID, &u.Username, &u.FullName, &u.Email, &u.Password, &u.Role, &u.ContactNumber, &u.IsActive, &u.Status)
		users = append(users, u)
	}
	sendJSON(c, http.StatusOK, users)
}

func handleToggleStatus(c *gin.Context) {
	id := c.Param("id")
	var req struct {
		Status   string `json:"status"`
		Role     string `json:"role"`
		IsActive bool   `json:"is_active"`
	}
	c.ShouldBindJSON(&req)

	_, err := db.Exec(context.Background(),
		"UPDATE users SET status=$1, role=COALESCE(NULLIF($2, ''), role), is_active=$3 WHERE id=$4",
		req.Status, req.Role, req.IsActive, id)

	if err != nil {
		sendError(c, 500, "Failed to update status", err)
		return
	}
	sendJSON(c, http.StatusOK, "Status Updated")
}

// --- INVENTORY HANDLERS ---

func handleGetInventory(c *gin.Context) {
	rows, _ := db.Query(context.Background(), "SELECT id, item, category, qty, threshold, unit, price, status FROM inventory ORDER BY item ASC")
	defer rows.Close()
	var list []Ingredient = []Ingredient{}
	for rows.Next() {
		var i Ingredient
		rows.Scan(&i.ID, &i.Item, &i.Category, &i.Qty, &i.Threshold, &i.Unit, &i.Price, &i.Status)
		list = append(list, i)
	}
	sendJSON(c, http.StatusOK, list)
}

func handleAddIngredient(c *gin.Context) {
	var i Ingredient
	c.ShouldBindJSON(&i)
	i.Status = calculateStatus(i.Qty, i.Threshold)
	err := db.QueryRow(context.Background(), "INSERT INTO inventory (item, category, qty, threshold, unit, price, status) VALUES ($1,$2,$3,$4,$5,$6,$7) RETURNING id",
		i.Item, i.Category, i.Qty, i.Threshold, i.Unit, i.Price, i.Status).Scan(&i.ID)
	if err != nil {
		sendError(c, 500, "Failed to add ingredient", err)
		return
	}
	sendJSON(c, http.StatusCreated, i)
}

func handleUpdateIngredient(c *gin.Context) {
	id := c.Param("id")
	var i Ingredient
	c.ShouldBindJSON(&i)
	i.Status = calculateStatus(i.Qty, i.Threshold)
	db.Exec(context.Background(), "UPDATE inventory SET item=$1, category=$2, qty=$3, threshold=$4, unit=$5, price=$6, status=$7 WHERE id=$8",
		i.Item, i.Category, i.Qty, i.Threshold, i.Unit, i.Price, i.Status, id)
	sendJSON(c, http.StatusOK, "Updated")
}

func handleDeleteIngredient(c *gin.Context) {
	db.Exec(context.Background(), "DELETE FROM inventory WHERE id=$1", c.Param("id"))
	sendJSON(c, 200, "Deleted")
}

// --- RECIPE / MEAL DIRECTORY HANDLERS ---

func handleGetRecipes(c *gin.Context) {
	query := `SELECT r.id, r.name, r.category, r.allergens, r.pax_size, r.price,
              COALESCE(json_agg(json_build_object('inventoryId', i.id, 'itemName', i.item, 'qty', ri.qty, 'unit', i.unit)) FILTER (WHERE ri.id IS NOT NULL), '[]')
              FROM recipes r LEFT JOIN recipe_ingredients ri ON r.id = ri.recipe_id LEFT JOIN inventory i ON ri.inventory_id = i.id
              GROUP BY r.id ORDER BY r.name ASC`
	rows, _ := db.Query(context.Background(), query)
	defer rows.Close()
	var recipes []Recipe = []Recipe{}
	for rows.Next() {
		var r Recipe
		var ingJSON []byte
		rows.Scan(&r.ID, &r.Name, &r.Category, &r.Allergens, &r.PaxSize, &r.Price, &ingJSON)
		json.Unmarshal(ingJSON, &r.Ingredients)
		recipes = append(recipes, r)
	}
	sendJSON(c, http.StatusOK, recipes)
}

func handleSaveRecipe(c *gin.Context) {
	var r Recipe
	if err := c.ShouldBindJSON(&r); err != nil {
		sendError(c, 400, "Invalid request", err)
		return
	}
	tx, _ := db.Begin(context.Background())
	defer tx.Rollback(context.Background())

	err := tx.QueryRow(context.Background(), "INSERT INTO recipes (name, category, allergens, pax_size, price) VALUES ($1,$2,$3,$4,$5) RETURNING id",
		r.Name, r.Category, r.Allergens, r.PaxSize, r.Price).Scan(&r.ID)
	if err != nil {
		sendError(c, 500, "Failed to save recipe", err)
		return
	}

	for _, ing := range r.Ingredients {
		_, err = tx.Exec(context.Background(), "INSERT INTO recipe_ingredients (recipe_id, inventory_id, qty) VALUES ($1,$2,$3)", r.ID, ing.InventoryID, ing.Qty)
		if err != nil {
			sendError(c, 500, "Failed to save ingredients", err)
			return
		}
	}
	tx.Commit(context.Background())
	sendJSON(c, http.StatusCreated, r)
}

func handleUpdateRecipe(c *gin.Context) {
	id := c.Param("id")
	var r Recipe
	c.ShouldBindJSON(&r)
	tx, _ := db.Begin(context.Background())
	defer tx.Rollback(context.Background())

	tx.Exec(context.Background(), "UPDATE recipes SET name=$1, category=$2, allergens=$3, pax_size=$4, price=$5 WHERE id=$6", r.Name, r.Category, r.Allergens, r.PaxSize, r.Price, id)
	tx.Exec(context.Background(), "DELETE FROM recipe_ingredients WHERE recipe_id=$1", id)

	for _, ing := range r.Ingredients {
		tx.Exec(context.Background(), "INSERT INTO recipe_ingredients (recipe_id, inventory_id, qty) VALUES ($1,$2,$3)", id, ing.InventoryID, ing.Qty)
	}
	tx.Commit(context.Background())
	sendJSON(c, http.StatusOK, "Updated")
}

func handleDeleteRecipe(c *gin.Context) {
	id := c.Param("id")
	// recipe_ingredients will be deleted automatically if you set up ON DELETE CASCADE in SQL
	_, err := db.Exec(context.Background(), "DELETE FROM recipes WHERE id=$1", id)
	if err != nil {
		sendError(c, 500, "Failed to delete recipe", err)
		return
	}
	sendJSON(c, 200, "Deleted")
}

// --- MEAL PLAN HANDLERS ---

func handleGetMealPlans(c *gin.Context) {
	rows, _ := db.Query(context.Background(), "SELECT id, date_from, date_to, status, plan_data FROM meal_plans ORDER BY id DESC")
	defer rows.Close()
	var plans []MealPlan = []MealPlan{}
	for rows.Next() {
		var p MealPlan
		rows.Scan(&p.ID, &p.DateFrom, &p.DateTo, &p.Status, &p.PlanData)
		plans = append(plans, p)
	}
	sendJSON(c, http.StatusOK, plans)
}

func handleSaveMealPlan(c *gin.Context) {
	var p MealPlan
	c.ShouldBindJSON(&p)
	db.QueryRow(context.Background(), "INSERT INTO meal_plans (date_from, date_to, status, plan_data) VALUES ($1,$2,$3,$4) RETURNING id", p.DateFrom, p.DateTo, "draft", p.PlanData).Scan(&p.ID)
	sendJSON(c, http.StatusCreated, p)
}

func handleUpdateMealPlanStatus(c *gin.Context) {
	id := c.Param("id")
	var req struct {
		Status string `json:"status"`
	}
	c.ShouldBindJSON(&req)
	db.Exec(context.Background(), "UPDATE meal_plans SET status=$1 WHERE id=$2", req.Status, id)
	sendJSON(c, http.StatusOK, "Status updated")
}

func handleGetActiveMenuForStudents(c *gin.Context) {
	var plan MealPlan
	err := db.QueryRow(context.Background(), "SELECT plan_data FROM meal_plans WHERE status='published' ORDER BY id DESC LIMIT 1").Scan(&plan.PlanData)
	if err != nil {
		sendJSON(c, http.StatusOK, nil)
		return
	}
	sendJSON(c, http.StatusOK, plan.PlanData)
}

func handleGetActivePlanIngredients(c *gin.Context) {
	var planData []byte
	err := db.QueryRow(context.Background(), "SELECT plan_data FROM meal_plans WHERE status='published' ORDER BY id DESC LIMIT 1").Scan(&planData)
	if err != nil || len(planData) == 0 {
		sendJSON(c, http.StatusOK, []interface{}{})
		return
	}

	var plans []struct {
		Meals struct {
			Breakfast struct {
				Items []struct {
					Name string
					Pax  int
				}
			} `json:"Breakfast"`
			Lunch struct {
				Items []struct {
					Name string
					Pax  int
				}
			} `json:"Lunch"`
			Snack struct {
				Items []struct {
					Name string
					Pax  int
				}
			} `json:"Snack"`
		} `json:"meals"`
	}
	json.Unmarshal(planData, &plans)

	totals := make(map[string]struct {
		Qty      float64
		Unit     string
		Category string
	})

	for _, day := range plans {
		allMeals := [][]struct {
			Name string
			Pax  int
		}{
			day.Meals.Breakfast.Items, day.Meals.Lunch.Items, day.Meals.Snack.Items,
		}
		for _, mealList := range allMeals {
			for _, item := range mealList {
				query := `SELECT i.item, i.unit, i.category, ri.qty, r.pax_size 
                          FROM recipes r JOIN recipe_ingredients ri ON r.id = ri.recipe_id JOIN inventory i ON ri.inventory_id = i.id
                          WHERE r.name = $1`
				rows, _ := db.Query(context.Background(), query, item.Name)
				for rows.Next() {
					var name, unit, cat string
					var ingQty float64
					var recipePax int
					rows.Scan(&name, &unit, &cat, &ingQty, &recipePax)
					if recipePax > 0 {
						multiplier := float64(item.Pax) / float64(recipePax)
						entry := totals[name]
						entry.Qty += ingQty * multiplier
						entry.Unit = unit
						entry.Category = cat
						totals[name] = entry
					}
				}
				rows.Close()
			}
		}
	}

	type FinalIng struct {
		Name     string  `json:"name"`
		Qty      float64 `json:"qty"`
		Unit     string  `json:"unit"`
		Category string  `json:"category"`
	}
	var result []FinalIng = []FinalIng{}
	for name, data := range totals {
		result = append(result, FinalIng{Name: name, Qty: data.Qty, Unit: data.Unit, Category: data.Category})
	}
	sendJSON(c, http.StatusOK, result)
}

// --- DASHBOARD HANDLERS ---

func handleGetDashboardOverview(c *gin.Context) {
	var stats struct {
		InStock  int `json:"inStock"`
		LowStock int `json:"lowStock"`
		NoStock  int `json:"noStock"`
	}
	db.QueryRow(context.Background(), "SELECT COUNT(*) FILTER (WHERE status='In Stock'), COUNT(*) FILTER (WHERE status='Low Stock'), COUNT(*) FILTER (WHERE status='No Stock') FROM inventory").Scan(&stats.InStock, &stats.LowStock, &stats.NoStock)
	sendJSON(c, http.StatusOK, stats)
}

func handleGetDashboardAnalytics(c *gin.Context) {
	rows, _ := db.Query(context.Background(), "SELECT category, COUNT(*) FROM inventory GROUP BY category")
	defer rows.Close()
	dist := make(map[string]int)
	for rows.Next() {
		var cat string
		var count int
		rows.Scan(&cat, &count)
		dist[cat] = count
	}
	sendJSON(c, http.StatusOK, gin.H{"categoryDistribution": dist})
}

// --- PROFILE & PASSWORD HANDLERS ---

func handleGetProfile(c *gin.Context) {
	id := c.Param("id")
	var u User
	err := db.QueryRow(context.Background(), "SELECT id, username, COALESCE(full_name,''), email, role, COALESCE(contact_number,'') FROM users WHERE id=$1", id).Scan(&u.ID, &u.Username, &u.FullName, &u.Email, &u.Role, &u.ContactNumber)
	if err != nil {
		sendError(c, 404, "User not found", err)
		return
	}
	sendJSON(c, http.StatusOK, u)
}

func handleUpdateProfile(c *gin.Context) {
	id := c.Param("id")
	var req struct {
		FullName string `json:"full_name"`
		Contact  string `json:"contact_number"`
	}
	c.ShouldBindJSON(&req)
	db.Exec(context.Background(), "UPDATE users SET full_name=$1, contact_number=$2 WHERE id=$3", req.FullName, req.Contact, id)
	sendJSON(c, http.StatusOK, "Profile Updated")
}

func handleForgotPassword(c *gin.Context) {
	var req struct {
		Email string `json:"email"`
	}
	c.ShouldBindJSON(&req)
	otp := fmt.Sprintf("%06d", time.Now().Nanosecond()%1000000)
	otpStore[req.Email] = otp
	body := fmt.Sprintf("Your code is: %s", otp)
	sendEmail(req.Email, "Reset Your StockMate Password", body)
	sendJSON(c, http.StatusOK, "OTP Sent")
}

func handleVerifyOTP(c *gin.Context) {
	var req struct{ Email, Code string }
	c.ShouldBindJSON(&req)
	if val, ok := otpStore[req.Email]; ok && val == req.Code {
		sendJSON(c, 200, "Verified")
		return
	}
	sendError(c, 400, "Invalid code", nil)
}

func handleChangePassword(c *gin.Context) {
	var req struct {
		Email    string `json:"email"`
		Password string `json:"password"`
	}
	c.ShouldBindJSON(&req)
	query := `UPDATE users SET password = $1 WHERE email = LOWER($2)`
	_, err := db.Exec(context.Background(), query, req.Password, req.Email)
	if err != nil {
		sendError(c, 500, "Failed to update password", err)
		return
	}
	delete(otpStore, req.Email)
	sendJSON(c, 200, "Password updated successfully")
}

func handleLogout(c *gin.Context) { sendJSON(c, http.StatusOK, "Logged out") }

func handleGetPendingCount(c *gin.Context) {
	var count int
	err := db.QueryRow(context.Background(), "SELECT COUNT(*) FROM users WHERE status='pending'").Scan(&count)
	if err != nil {
		sendJSON(c, http.StatusOK, 0)
		return
	}
	sendJSON(c, http.StatusOK, count)
}

func handleDeleteUser(c *gin.Context) {
	db.Exec(context.Background(), "DELETE FROM users WHERE id=$1", c.Param("id"))
	sendJSON(c, 200, "Deleted")
}
