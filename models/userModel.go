package models

import "gorm.io/gorm"

type Customer struct {
	gorm.Model
	Email 		string `gorm:"unique"`
	Password 	string
}