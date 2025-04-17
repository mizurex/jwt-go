package middleware

import (
	"go-jwt/initializers"
	"go-jwt/models"
	"net/http"
	"os"
	"time"
	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	
)

func RequireAuth(c *gin.Context) {
	// Get the Cookie off the request
	tokenString, err := c.Cookie("Authorization")

	if err != nil {
		// Handle error gracefully and return unauthorized status
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized, token missing or invalid"})
		c.Abort()
		return
	}

	// Decode and validate the token
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		return []byte(os.Getenv("SECRET")), nil
	})

	if err != nil {
		// Log error but don't stop the execution; instead, return a response
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized, token invalid"})
		c.Abort()
		return
	}

	if claims, ok := token.Claims.(jwt.MapClaims); ok {
		// Check the expiration time
		if float64(time.Now().Unix()) > claims["exp"].(float64) {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Token expired"})
			c.Abort()
			return
		}

		// Find the user with the token's subject (sub claim)
		var customer models.Customer
		result := initializers.DB.First(&customer, claims["sub"])

		if result.Error != nil || customer.ID == 0 {
			// If no customer is found or there's an error
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid user associated with token"})
			c.Abort()
			return
		}

		// Attach the customer to the request context
		c.Set("customer", customer)
		// Proceed to the next middleware or handler
		c.Next()
	} else {
		// If the token claims are not in the expected format
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid token format"})
		c.Abort()
	}
}