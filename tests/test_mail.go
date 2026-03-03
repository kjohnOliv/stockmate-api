package main

import (
	"fmt"
	"net/smtp"
	"os"

	"github.com/joho/godotenv"
)

func main() {
	// 1. Try to load the .env file
	err := godotenv.Load("../.env")
	if err != nil {
		fmt.Println("⚠️  Could not find .env in parent folder, checking current folder...")
		godotenv.Load(".env")
	}

	// 2. Pull variables
	from := os.Getenv("SMTP_USER")
	pass := os.Getenv("SMTP_PASS")
	host := os.Getenv("SMTP_HOST")
	port := os.Getenv("SMTP_PORT")

	// 3. Debugging: Check if variables are empty
	fmt.Printf("--- SMTP Debug Info ---\n")
	fmt.Printf("User: %s\n", from)
	fmt.Printf("Host: %s\n", host)
	fmt.Printf("Port: %s\n", port)
	fmt.Printf("Pass Length: %d characters\n", len(pass))
	fmt.Printf("-----------------------\n")

	if from == "" || host == "" || port == "" {
		fmt.Println("❌ Error: One or more SMTP variables are empty in your .env file!")
		return
	}

	// 4. Attempt to send
	to := from
	msg := "Subject: StockMate SMTP Test\n" +
		"Mime-Version: 1.0;\n" +
		"Content-Type: text/html; charset=\"UTF-8\";\n\n" +
		"<h1>✅ Success!</h1><p>Your Go backend is talking to the SMTP server.</p>"

	auth := smtp.PlainAuth("", from, pass, host)

	fmt.Println("Connecting to server...")
	err = smtp.SendMail(host+":"+port, auth, from, []string{to}, []byte(msg))

	if err != nil {
		fmt.Printf("❌ Connection Failed: %v\n", err)
	} else {
		fmt.Println("🚀 Success! Check your inbox.")
	}
}
