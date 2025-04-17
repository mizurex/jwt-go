package controllers

import (
	"go-jwt/initializers"
	"go-jwt/models"
	"net/http"
	"os"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/crypto/bcrypt"
)

func Signup(c *gin.Context) {

	//Get the Email/Password off the body
	var body struct {
		Email    string
		Password string
	}
	if c.BindJSON(&body) != nil {
		c.JSON(http.StatusBadRequest, gin.H{"message": "Invalid JSON"})
		return
	}

	//Hash the Password
	hash, err := bcrypt.GenerateFromPassword([]byte(body.Password), 10)

	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "failed to hash password"})
		return
	}

	//Create the user
	customer := models.Customer{Email: body.Email, Password: string(hash)}

	result := initializers.DB.Create(&customer)

	if result.Error != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "failed to create user"})
		return
	}

	//Respond
	c.JSON(http.StatusOK, gin.H{})
}

func Login(c *gin.Context) {
	//Get the email/pass off body
	var body struct {
		Email    string
		Password string
	}
	if c.BindJSON(&body) != nil {
		c.JSON(http.StatusBadRequest, gin.H{"message": "Invalid JSON"})
		return
	}

	//Look up requested user
	var customer models.Customer
	result := initializers.DB.First(&customer, "email = ?", body.Email)

	if result.Error != nil {
		c.JSON(http.StatusBadRequest, gin.H{"message": "Invalid Email or Password"})
		return
	}
	//Compare the pass in the db
	err := bcrypt.CompareHashAndPassword([]byte(customer.Password), []byte(body.Password))

	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"message": "Invalid Password"})
		return
	}

	//Generate JWT token
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"sub": customer.ID,
		"exp": time.Now().Add(time.Hour * 24 * 30).Unix(),
	})

	// Sign and get the complete encoded token as a string using the secret
	tokenString, err := token.SignedString([]byte(os.Getenv("SECRET")))

	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"message": "failed to create token"})
		return
	}
	// send it back
	c.SetSameSite(http.SameSiteLaxMode)
	c.SetCookie("Authorization",tokenString,3600*24*30,"","",false,true)

	c.JSON(http.StatusOK, gin.H{})
}

func Validate(c*gin.Context){
	customer,_ := c.Get("customer")
	c.JSON(http.StatusOK,gin.H{"message":customer})

}