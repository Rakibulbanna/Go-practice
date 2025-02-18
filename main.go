package main

import (
	"database/sql"
	"errors"
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/gin-gonic/gin"
	_ "github.com/go-sql-driver/mysql"
	"golang.org/x/crypto/bcrypt"
)

// Secret key for JWT
var jwtSecret = []byte("your_secret_key")

// Database connection
var db *sql.DB

func ConnectDatabase() {
	var err error
	dsn := "root:password@tcp(127.0.0.1:4000)/go_crud"
	db, err = sql.Open("mysql", dsn)
	if err != nil {
		log.Fatal("Failed to connect to database: ", err)
	}

	// Test the connection
	err = db.Ping()
	if err != nil {
		log.Fatal("Database not reachable: ", err)
	}
	fmt.Println("Database connected")
}

func main() {
	ConnectDatabase()

	r := gin.Default()

	// Public Routes
	r.POST("/register", RegisterUser)
	r.POST("/login", LoginUser)

	// Protected Routes (Require Authentication)
	protected := r.Group("/users")
	protected.Use(AuthMiddleware())
	{
		protected.GET("", GetUsers)
		protected.GET("/:id", GetUserByID)
		protected.PUT("/:id", UpdateUser)
		protected.DELETE("/:id", DeleteUser)
	}

	r.Run(":8080")
}

// Error response struct
type ErrorResponse struct {
	Error   string `json:"error"`
	Message string `json:"message"`
}

// Success response struct
type SuccessResponse struct {
	Message string `json:"message"`
	Data    any    `json:"data,omitempty"`
}

// Hash password
func HashPassword(password string) (string, error) {
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	return string(hashedPassword), err
}

// Check password
func CheckPassword(hashedPassword, password string) error {
	return bcrypt.CompareHashAndPassword([]byte(hashedPassword), []byte(password))
}

// Generate JWT token
func GenerateToken(userID int) (string, error) {
	claims := jwt.MapClaims{
		"user_id": userID,
		"exp":     time.Now().Add(time.Hour * 24).Unix(), // Token expires in 24 hours
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString(jwtSecret)
}

// Middleware for authentication
func AuthMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		tokenString := c.GetHeader("Authorization")
		// fmt.Println("tokenString___", tokenString)
		if tokenString == "" {
			c.JSON(http.StatusUnauthorized, ErrorResponse{"Unauthorized", "Missing token"})
			c.Abort()
			return
		}

		claims := jwt.MapClaims{}
		token, err := jwt.ParseWithClaims(tokenString, claims, func(token *jwt.Token) (interface{}, error) {
			return jwtSecret, nil
		})

		if err != nil || !token.Valid {
			c.JSON(http.StatusUnauthorized, ErrorResponse{"Unauthorized", "Invalid token"})
			c.Abort()
			return
		}

		// Attach user ID to context
		c.Set("user_id", int(claims["user_id"].(float64)))
		c.Next()
	}
}

// Register new user
func RegisterUser(c *gin.Context) {
	var user struct {
		Name     string `json:"name"`
		Email    string `json:"email"`
		Password string `json:"password"`
	}
	if err := c.ShouldBindJSON(&user); err != nil {
		c.JSON(http.StatusBadRequest, ErrorResponse{"Invalid Input", err.Error()})
		return
	}

	// Hash password
	hashedPassword, err := HashPassword(user.Password)
	if err != nil {
		c.JSON(http.StatusInternalServerError, ErrorResponse{"Error", "Failed to hash password"})
		return
	}

	query := "INSERT INTO users (name, email, password) VALUES (?, ?, ?)"
	_, err = db.Exec(query, user.Name, user.Email, hashedPassword)
	if err != nil {
		c.JSON(http.StatusConflict, ErrorResponse{"Conflict", "Email already exists"})
		return
	}

	c.JSON(http.StatusCreated, SuccessResponse{"User registered successfully", nil})
}

// Login user and return JWT token
func LoginUser(c *gin.Context) {
	var login struct {
		Email    string `json:"email"`
		Password string `json:"password"`
	}
	if err := c.ShouldBindJSON(&login); err != nil {
		c.JSON(http.StatusBadRequest, ErrorResponse{"Invalid Input", err.Error()})
		return
	}

	var user struct {
		ID       int
		Email    string
		Password string
	}
	query := "SELECT id, email, password FROM users WHERE email = ?"
	err := db.QueryRow(query, login.Email).Scan(&user.ID, &user.Email, &user.Password)
	if err != nil {
		c.JSON(http.StatusUnauthorized, ErrorResponse{"Unauthorized", "Invalid email or password"})
		return
	}

	// Check password
	if err := CheckPassword(user.Password, login.Password); err != nil {
		c.JSON(http.StatusUnauthorized, ErrorResponse{"Unauthorized", "Invalid email or password"})
		return
	}

	// Generate JWT
	token, err := GenerateToken(user.ID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, ErrorResponse{"Error", "Failed to generate token"})
		return
	}

	c.JSON(http.StatusOK, SuccessResponse{"Login successful", map[string]string{"token": token}})
}

// Get all users (Protected)
func GetUsers(c *gin.Context) {
	query := "SELECT id, name, email FROM users"
	rows, err := db.Query(query)
	if err != nil {
		c.JSON(http.StatusInternalServerError, ErrorResponse{"Database Error", err.Error()})
		return
	}
	defer rows.Close()

	var users []map[string]any
	for rows.Next() {
		var id int
		var name, email string
		rows.Scan(&id, &name, &email)
		users = append(users, map[string]any{"id": id, "name": name, "email": email})
	}

	c.JSON(http.StatusOK, SuccessResponse{"Users retrieved successfully", users})
}

// Get user by ID (Protected)
func GetUserByID(c *gin.Context) {
	id := c.Param("id")

	query := "SELECT id, name, email FROM users WHERE id = ?"
	row := db.QueryRow(query, id)

	var user struct {
		ID    int    `json:"id"`
		Name  string `json:"name"`
		Email string `json:"email"`
	}

	err := row.Scan(&user.ID, &user.Name, &user.Email)
	if err != nil {
		c.JSON(http.StatusNotFound, ErrorResponse{"Not Found", "User does not exist"})
		return
	}

	c.JSON(http.StatusOK, SuccessResponse{"User retrieved successfully", user})
}

// Update a user
func UpdateUser(c *gin.Context) {
	id := c.Param("id")
	var user struct {
		Name  string `json:"name"`
		Email string `json:"email"`
	}
	if err := c.ShouldBindJSON(&user); err != nil {
		c.JSON(http.StatusBadRequest, ErrorResponse{"Invalid Input", err.Error()})
		return
	}

	query := "UPDATE users SET name = ?, email = ? WHERE id = ?"
	result, err := db.Exec(query, user.Name, user.Email, id)
	if err != nil {
		if isDuplicateEntryError(err) {
			c.JSON(http.StatusConflict, ErrorResponse{"Conflict", "Email already exists"})
			return
		}
		c.JSON(http.StatusInternalServerError, ErrorResponse{"Database Error", err.Error()})
		return
	}

	rowsAffected, _ := result.RowsAffected()
	if rowsAffected == 0 {
		c.JSON(http.StatusNotFound, ErrorResponse{"Not Found", "User does not exist"})
		return
	}

	c.JSON(http.StatusOK, SuccessResponse{"User updated successfully", nil})
}

// Delete a user
func DeleteUser(c *gin.Context) {
	id := c.Param("id")

	query := "DELETE FROM users WHERE id = ?"
	result, err := db.Exec(query, id)
	if err != nil {
		c.JSON(http.StatusInternalServerError, ErrorResponse{"Database Error", err.Error()})
		return
	}

	rowsAffected, _ := result.RowsAffected()
	if rowsAffected == 0 {
		c.JSON(http.StatusNotFound, ErrorResponse{"Not Found", "User does not exist"})
		return
	}

	c.JSON(http.StatusOK, SuccessResponse{"User deleted successfully", nil})
}

// Check for duplicate entry error
func isDuplicateEntryError(err error) bool {
	return err != nil && errors.Is(err, sql.ErrNoRows)
}
