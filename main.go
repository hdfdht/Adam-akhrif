package main

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"log"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/go-redis/redis/v8"
	"github.com/golang-jwt/jwt/v5"
	"github.com/gorilla/mux"
	"github.com/gorilla/websocket"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
	"golang.org/x/crypto/bcrypt"
)

var (
	ctx = context.Background()

	mongoURI  = os.Getenv("MONGODB_URI")
	redisAddr = os.Getenv("REDIS_ADDR")
	redisPass = os.Getenv("REDIS_PASSWORD")
	jwtSecret = []byte(os.Getenv("JWT_SECRET"))

	aesKeyB64 = os.Getenv("AES_KEY_BASE64")
	aesKey    []byte

	mongoCli *mongo.Client
	db       *mongo.Database
	redisCli *redis.Client

	upgrader = websocket.Upgrader{
		CheckOrigin: func(r *http.Request) bool { return true },
	}

	clients   = make(map[*websocket.Conn]string) // websocket clients map: conn => username
	clientsMu sync.Mutex
)

type User struct {
	ID           primitive.ObjectID `bson:"_id,omitempty" json:"id"`
	Username     string             `bson:"username" json:"username"`
	PasswordHash string             `bson:"password_hash,omitempty" json:"-"`
	Email        string             `bson:"email,omitempty" json:"email,omitempty"`
	Phone        string             `bson:"phone,omitempty" json:"phone,omitempty"`
	Roles        []string           `bson:"roles" json:"roles"`
	Points       int                `bson:"points" json:"points"`
	Telegram     string             `bson:"telegram,omitempty" json:"telegram,omitempty"`
	Discord      string             `bson:"discord,omitempty" json:"discord,omitempty"`
	Instagram    string             `bson:"instagram,omitempty" json:"instagram,omitempty"`
	Twitter      string             `bson:"twitter,omitempty" json:"twitter,omitempty"`
	CreatedAt    time.Time          `bson:"created_at" json:"created_at"`
	LastActive   time.Time          `bson:"last_active" json:"last_active"`
}

type Message struct {
	ID         primitive.ObjectID  `bson:"_id,omitempty" json:"id"`
	SenderID   primitive.ObjectID  `bson:"sender_id" json:"sender_id"`
	Username   string              `bson:"username" json:"username"` // sender username for easier broadcast
	Content    string              `bson:"content" json:"content"`
	MediaType  string              `bson:"media_type,omitempty" json:"media_type,omitempty"`
	MediaURL   string              `bson:"media_url,omitempty" json:"media_url,omitempty"`
	Timestamp  time.Time           `bson:"timestamp" json:"timestamp"`
	Deleted    bool                `bson:"deleted" json:"deleted"`
	ReplyTo    *primitive.ObjectID `bson:"reply_to,omitempty" json:"reply_to,omitempty"`
	IsFiltered bool                `bson:"is_filtered" json:"is_filtered"`
}

// AES-GCM encryption / decryption helpers
func encryptAESGCM(key, plaintext []byte) (string, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}
	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	nonce := make([]byte, aesgcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", err
	}
	ct := aesgcm.Seal(nonce, nonce, plaintext, nil)
	return base64.StdEncoding.EncodeToString(ct), nil
}

func decryptAESGCM(key []byte, encoded string) ([]byte, error) {
	data, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonceSize := aesgcm.NonceSize()
	if len(data) < nonceSize {
		return nil, errors.New("ciphertext too short")
	}
	nonce, ciphertext := data[:nonceSize], data[nonceSize:]
	return aesgcm.Open(nil, nonce, ciphertext, nil)
}

// JWT Claims with roles + username + userID
type CustomClaims struct {
	UserID   string   `json:"user_id"`
	Username string   `json:"username"`
	Roles    []string `json:"roles"`
	jwt.RegisteredClaims
}

// Generate JWT with 24h expiry (قوي وآمن)
func generateJWT(userID, username string, roles []string) (string, error) {
	claims := CustomClaims{
		UserID:   userID,
		Username: username,
		Roles:    roles,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(24 * time.Hour)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			Issuer:    "mega-chat-pro",
		},
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString(jwtSecret)
}

func validateJWT(tokenStr string) (*CustomClaims, error) {
	token, err := jwt.ParseWithClaims(tokenStr, &CustomClaims{}, func(t *jwt.Token) (interface{}, error) {
		return jwtSecret, nil
	})
	if err != nil {
		return nil, err
	}
	if claims, ok := token.Claims.(*CustomClaims); ok && token.Valid {
		return claims, nil
	}
	return nil, errors.New("invalid token")
}

// Middleware: تحقق من التوثيق والاضافة لـ Context
func authMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authHeader := r.Header.Get("Authorization")
		if authHeader == "" {
			http.Error(w, "missing authorization header", http.StatusUnauthorized)
			return
		}
		tokenStr := strings.TrimPrefix(authHeader, "Bearer ")
		claims, err := validateJWT(tokenStr)
		if err != nil {
			http.Error(w, "invalid token", http.StatusUnauthorized)
			return
		}
		ctx := context.WithValue(r.Context(), "claims", claims)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// Register endpoint مع تحقق صارم + تنظيف المدخلات + تسجيل المستخدم
func registerHandler(w http.ResponseWriter, r *http.Request) {
	type req struct {
		Username  string `json:"username"`
		Email     string `json:"email"`
		Password  string `json:"password"`
		Telegram  string `json:"telegram,omitempty"`
		Discord   string `json:"discord,omitempty"`
		Instagram string `json:"instagram,omitempty"`
		Twitter   string `json:"twitter,omitempty"`
	}
	var body req
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return
	}
	// Validation minimal
	if len(body.Username) < 3 || len(body.Password) < 6 {
		http.Error(w, "username must be >=3 chars and password >=6 chars", http.StatusBadRequest)
		return
	}
	body.Username = strings.TrimSpace(body.Username)
	body.Email = strings.TrimSpace(body.Email)

	usersCol := db.Collection("users")
	count, err := usersCol.CountDocuments(ctx, bson.M{"username": body.Username})
	if err != nil {
		http.Error(w, "server error", http.StatusInternalServerError)
		return
	}
	if count > 0 {
		http.Error(w, "username already taken", http.StatusConflict)
		return
	}

	passHash, err := bcrypt.GenerateFromPassword([]byte(body.Password), bcrypt.DefaultCost)
	if err != nil {
		http.Error(w, "server error hashing password", http.StatusInternalServerError)
		return
	}

	now := time.Now()
	user := User{
		Username:     body.Username,
		Email:        body.Email,
		PasswordHash: string(passHash),
		Roles:        []string{"User"},
		Points:       0,
		Telegram:     body.Telegram,
		Discord:      body.Discord,
		Instagram:    body.Instagram,
		Twitter:      body.Twitter,
		CreatedAt:    now,
		LastActive:   now,
	}

	res, err := usersCol.InsertOne(ctx, user)
	if err != nil {
		http.Error(w, "failed to create user", http.StatusInternalServerError)
		return
	}

	json.NewEncoder(w).Encode(map[string]interface{}{
		"ok": true,
		"id": res.InsertedID,
	})
}

// Login endpoint + تحديث آخر نشاط واص