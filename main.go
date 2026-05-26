package main

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"sort"
	"strings"
	"sync/atomic"
	"time"

	"github.com/google/uuid"
	"github.com/joho/godotenv"
	_ "github.com/lib/pq"

	"chirpy/internal/auth"
	"chirpy/internal/database"
)

type apiConfig struct {
	fileserverHits atomic.Int32
	dbQueries      *database.Queries
	platform       string
	jwtSecret      string
	polkaKey       string
}

type User struct {
	ID        uuid.UUID `json:"id"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
	Email     string    `json:"email"`
	// HashedPassword string    `json:"-"`
	IsChirpyRed bool `json:"is_chirpy_red"`
}

type webhookRequest struct {
	Event string `json:"event"`
	Data  struct {
		UserID string `json:"user_id"`
	} `json:"data"`
}

type validateChirpRequest struct {
	Body string `json:"body"`
}

type validateChirpResponse struct {
	CleanedBody string `json:"cleaned_body"`
}

type errorResponse struct {
	Error string `json:"error"`
}

type Chirp struct {
	ID        uuid.UUID `json:"id"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
	Body      string    `json:"body"`
	UserID    uuid.UUID `json:"user_id"`
}

type createChirpRequest struct {
	Body string `json:"body"`
}

type createUserRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

type loginRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

type updateUserRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

var profaneWords = map[string]bool{
	"kerfuffle": true,
	"sharbert":  true,
	"fornax":    true,
}

func main() {
	err := godotenv.Load()
	if err != nil {
		fmt.Printf("Warning: .env file not found: %v\n", err)
	}

	polkaKey := os.Getenv("POLKA_KEY")
	if polkaKey == "" {
		fmt.Println("POLKA_KEY environment variable not set")
		os.Exit(1)
	}

	dbURL := os.Getenv("DB_URL")
	if dbURL == "" {
		fmt.Println("DB_URL environment variable not set")
		os.Exit(1)
	}

	platform := os.Getenv("PLATFORM")
	if platform == "" {
		fmt.Println("PLATFORM environment variable not set, defaulting to 'dev'")
		platform = "dev"
	}

	db, err := sql.Open("postgres", dbURL)
	if err != nil {
		fmt.Printf("Error opening database: %v\n", err)
		os.Exit(1)
	}

	err = db.Ping()
	if err != nil {
		fmt.Printf("Error connecting to database: %v\n", err)
		os.Exit(1)
	}

	fmt.Println("Successfully connected to database")

	dbQueries := database.New(db)

	jwtSecret := os.Getenv("JWT_SECRET")
	if jwtSecret == "" {
		fmt.Println("JWT_SECRET environment variable not set")
		os.Exit(1)
	}

	apiCfg := &apiConfig{
		dbQueries: dbQueries,
		platform:  platform,
		jwtSecret: jwtSecret,
		polkaKey:  polkaKey,
	}

	mux := http.NewServeMux()

	fileServer := http.FileServer(http.Dir("."))

	mux.Handle("/app/", apiCfg.middlewareMetricsInc(http.StripPrefix("/app", fileServer)))

	mux.HandleFunc("GET /api/healthz", readinessHandler)
	mux.HandleFunc("POST /api/chirps", apiCfg.createChirpHandler)
	mux.HandleFunc("GET /api/chirps", apiCfg.getChirpsHandler)
	mux.HandleFunc("GET /api/chirps/{chirpID}", apiCfg.getChirpHandler)
	mux.HandleFunc("POST /api/users", apiCfg.createUserHandler)
	mux.HandleFunc("POST /api/login", apiCfg.loginHandler)
	mux.HandleFunc("POST /api/refresh", apiCfg.refreshHandler)
	mux.HandleFunc("POST /api/revoke", apiCfg.revokeHandler)
	mux.HandleFunc("PUT /api/users", apiCfg.updateUserHandler)
	mux.HandleFunc("DELETE /api/chirps/{chirpID}", apiCfg.deleteChirpHandler)
	mux.HandleFunc("POST /api/polka/webhooks", apiCfg.polkaWebhookHandler)

	mux.HandleFunc("GET /admin/metrics", apiCfg.adminMetricsHandler)
	mux.HandleFunc("POST /admin/reset", apiCfg.resetHandler)

	server := &http.Server{
		Addr:    ":8080",
		Handler: mux,
	}

	server.ListenAndServe()
}

func readinessHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("OK"))
}

func (cfg *apiConfig) createChirpHandler(w http.ResponseWriter, r *http.Request) {
	// Only accept POST requests
	if r.Method != http.MethodPost {
		respondWithError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}

	// Get the bearer token from the Authorization header
	tokenString, err := auth.GetBearerToken(r.Header)
	if err != nil {
		respondWithError(w, http.StatusUnauthorized, "Missing or invalid authorization header")
		return
	}

	// Validate the JWT token
	userID, err := auth.ValidateJWT(tokenString, cfg.jwtSecret)
	if err != nil {
		respondWithError(w, http.StatusUnauthorized, "Invalid or expired token")
		return
	}

	// Decode the JSON request body
	var req struct {
		Body string `json:"body"`
	}
	err = json.NewDecoder(r.Body).Decode(&req)
	if err != nil {
		respondWithError(w, http.StatusBadRequest, "Invalid request body")
		return
	}

	// Validate the chirp body
	if req.Body == "" {
		respondWithError(w, http.StatusBadRequest, "Chirp body is required")
		return
	}

	// Check if the chirp is too long (more than 140 characters)
	if len(req.Body) > 140 {
		respondWithError(w, http.StatusBadRequest, "Chirp is too long")
		return
	}

	// Clean the chirp by replacing profane words
	cleanedBody := replaceProfaneWords(req.Body)

	// Create the chirp in the database using the userID from the token
	dbChirp, err := cfg.dbQueries.CreateChirp(r.Context(), database.CreateChirpParams{
		Body:   cleanedBody,
		UserID: userID, // Use the userID from the JWT
	})
	if err != nil {
		respondWithError(w, http.StatusInternalServerError, "Failed to create chirp")
		fmt.Printf("Error creating chirp: %v\n", err)
		return
	}

	// Map database chirp to our main Chirp struct
	chirp := Chirp{
		ID:        dbChirp.ID,
		CreatedAt: dbChirp.CreatedAt,
		UpdatedAt: dbChirp.UpdatedAt,
		Body:      dbChirp.Body,
		UserID:    dbChirp.UserID,
	}

	// Return the created chirp with 201 status
	respondWithJSON(w, http.StatusCreated, chirp)
}

func (cfg *apiConfig) loginHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		respondWithError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}

	// Parse request body
	var req loginRequest
	err := json.NewDecoder(r.Body).Decode(&req)
	if err != nil {
		respondWithError(w, http.StatusBadRequest, "Invalid request body")
		return
	}

	if req.Email == "" || req.Password == "" {
		respondWithError(w, http.StatusBadRequest, "Email and password are required")
		return
	}

	// Get user by email
	dbUser, err := cfg.dbQueries.GetUserByEmail(r.Context(), req.Email)
	if err != nil {
		if err == sql.ErrNoRows {
			respondWithError(w, http.StatusUnauthorized, "Incorrect email or password")
			return
		}
		respondWithError(w, http.StatusInternalServerError, "Failed to login")
		fmt.Printf("Error getting user: %v\n", err)
		return
	}

	// Check password
	match, err := auth.CheckPasswordHash(req.Password, dbUser.HashedPassword)
	if err != nil || !match {
		respondWithError(w, http.StatusUnauthorized, "Incorrect email or password")
		return
	}

	// Create access token (expires in 1 hour)
	accessToken, err := auth.MakeJWT(dbUser.ID, cfg.jwtSecret, time.Hour)
	if err != nil {
		respondWithError(w, http.StatusInternalServerError, "Failed to create access token")
		fmt.Printf("Error creating JWT: %v\n", err)
		return
	}

	// Create refresh token (expires in 60 days)
	refreshTokenString, err := auth.MakeRefreshToken()
	if err != nil {
		respondWithError(w, http.StatusInternalServerError, "Failed to create refresh token")
		fmt.Printf("Error creating refresh token: %v\n", err)
		return
	}

	// Calculate expiration time for refresh token (60 days)
	expiresAt := time.Now().UTC().Add(60 * 24 * time.Hour)

	// Store refresh token in database
	err = cfg.dbQueries.CreateRefreshToken(r.Context(), database.CreateRefreshTokenParams{
		Token:     refreshTokenString,
		UserID:    dbUser.ID,
		ExpiresAt: expiresAt,
	})
	if err != nil {
		respondWithError(w, http.StatusInternalServerError, "Failed to store refresh token")
		fmt.Printf("Error storing refresh token: %v\n", err)
		return
	}

	// Return user with tokens
	user := User{
		ID:          dbUser.ID,
		CreatedAt:   dbUser.CreatedAt,
		UpdatedAt:   dbUser.UpdatedAt,
		Email:       dbUser.Email,
		IsChirpyRed: dbUser.IsChirpyRed,
	}

	// Create response with both tokens
	response := struct {
		User
		Token        string `json:"token"`
		RefreshToken string `json:"refresh_token"`
	}{
		User:         user,
		Token:        accessToken,
		RefreshToken: refreshTokenString,
	}

	respondWithJSON(w, http.StatusOK, response)

}

func (cfg *apiConfig) createUserHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		respondWithError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}

	// Parse request body
	var req createUserRequest
	err := json.NewDecoder(r.Body).Decode(&req)
	if err != nil {
		respondWithError(w, http.StatusBadRequest, "Invalid request body")
		return
	}

	if req.Email == "" {
		respondWithError(w, http.StatusBadRequest, "Email is required")
		return
	}

	if req.Password == "" {
		respondWithError(w, http.StatusBadRequest, "Password is required")
		return
	}

	// Hash the password
	hashedPassword, err := auth.HashPassword(req.Password)
	if err != nil {
		respondWithError(w, http.StatusInternalServerError, "Failed to create user")
		fmt.Printf("Error hashing password: %v\n", err)
		return
	}

	// Create user using SQLC generated query (need to update this)
	// You'll need to update your CreateUser query to include hashed_password
	dbUser, err := cfg.dbQueries.CreateUser(r.Context(), database.CreateUserParams{
		Email:          req.Email,
		HashedPassword: hashedPassword,
	})
	if err != nil {
		respondWithError(w, http.StatusInternalServerError, "Failed to create user")
		fmt.Printf("Error creating user: %v\n", err)
		return
	}

	// Map database user to our main User struct for JSON marshaling
	user := User{
		ID:          dbUser.ID,
		CreatedAt:   dbUser.CreatedAt,
		UpdatedAt:   dbUser.UpdatedAt,
		Email:       dbUser.Email,
		IsChirpyRed: dbUser.IsChirpyRed,
		// Don't include HashedPassword in response
	}

	// Return the created user with 201 status
	respondWithJSON(w, http.StatusCreated, user)
}

func (cfg *apiConfig) updateUserHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPut {
		respondWithError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}

	// Get the bearer token from the Authorization header
	tokenString, err := auth.GetBearerToken(r.Header)
	if err != nil {
		respondWithError(w, http.StatusUnauthorized, "Missing or invalid authorization header")
		return
	}

	// Validate the JWT token and get user ID
	userID, err := auth.ValidateJWT(tokenString, cfg.jwtSecret)
	if err != nil {
		respondWithError(w, http.StatusUnauthorized, "Invalid or expired token")
		return
	}

	// Parse request body
	var req updateUserRequest
	err = json.NewDecoder(r.Body).Decode(&req)
	if err != nil {
		respondWithError(w, http.StatusBadRequest, "Invalid request body")
		return
	}

	// Validate request
	if req.Email == "" {
		respondWithError(w, http.StatusBadRequest, "Email is required")
		return
	}

	if req.Password == "" {
		respondWithError(w, http.StatusBadRequest, "Password is required")
		return
	}

	// Hash the new password
	hashedPassword, err := auth.HashPassword(req.Password)
	if err != nil {
		respondWithError(w, http.StatusInternalServerError, "Failed to update user")
		fmt.Printf("Error hashing password: %v\n", err)
		return
	}

	// Update the user in the database
	dbUser, err := cfg.dbQueries.UpdateUser(r.Context(), database.UpdateUserParams{
		Email:          req.Email,
		HashedPassword: hashedPassword,
		ID:             userID,
	})
	if err != nil {
		if err == sql.ErrNoRows {
			respondWithError(w, http.StatusNotFound, "User not found")
			return
		}
		respondWithError(w, http.StatusInternalServerError, "Failed to update user")
		fmt.Printf("Error updating user: %v\n", err)
		return
	}

	// Map database user to our main User struct
	user := User{
		ID:        dbUser.ID,
		CreatedAt: dbUser.CreatedAt,
		UpdatedAt: dbUser.UpdatedAt,
		Email:     dbUser.Email,
		// Don't include HashedPassword in response
		IsChirpyRed: dbUser.IsChirpyRed,
	}

	// Return the updated user
	respondWithJSON(w, http.StatusOK, user)
}

func (cfg *apiConfig) refreshHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		respondWithError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}

	// Get the bearer token from the Authorization header
	refreshToken, err := auth.GetBearerToken(r.Header)
	if err != nil {
		respondWithError(w, http.StatusUnauthorized, "Missing or invalid authorization header")
		return
	}

	// Get user from refresh token
	dbUser, err := cfg.dbQueries.GetUserFromRefreshToken(r.Context(), refreshToken)
	if err != nil {
		if err == sql.ErrNoRows {
			respondWithError(w, http.StatusUnauthorized, "Invalid, expired, or revoked refresh token")
			return
		}
		respondWithError(w, http.StatusInternalServerError, "Failed to validate refresh token")
		fmt.Printf("Error getting user from refresh token: %v\n", err)
		return
	}

	// Create new access token (expires in 1 hour)
	accessToken, err := auth.MakeJWT(dbUser.ID, cfg.jwtSecret, time.Hour)
	if err != nil {
		respondWithError(w, http.StatusInternalServerError, "Failed to create access token")
		fmt.Printf("Error creating JWT: %v\n", err)
		return
	}

	// Return the new access token
	response := struct {
		Token string `json:"token"`
	}{
		Token: accessToken,
	}

	respondWithJSON(w, http.StatusOK, response)
}

func (cfg *apiConfig) revokeHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		respondWithError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}

	// Get the bearer token from the Authorization header
	refreshToken, err := auth.GetBearerToken(r.Header)
	if err != nil {
		respondWithError(w, http.StatusUnauthorized, "Missing or invalid authorization header")
		return
	}

	// Revoke the refresh token in the database
	err = cfg.dbQueries.RevokeRefreshToken(r.Context(), refreshToken)
	if err != nil {
		if err == sql.ErrNoRows {
			respondWithError(w, http.StatusUnauthorized, "Refresh token not found")
			return
		}
		respondWithError(w, http.StatusInternalServerError, "Failed to revoke refresh token")
		fmt.Printf("Error revoking refresh token: %v\n", err)
		return
	}

	// Return 204 No Content
	w.WriteHeader(http.StatusNoContent)
}

func (cfg *apiConfig) getChirpsHandler(w http.ResponseWriter, r *http.Request) {
	// Only accept GET requests
	if r.Method != http.MethodGet {
		respondWithError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}

	// Check for author_id query parameter
	authorIDStr := r.URL.Query().Get("author_id")

	// Check for sort query parameter
	sortParam := r.URL.Query().Get("sort")

	var dbChirps []database.Chirp
	var err error

	if authorIDStr != "" {
		// Parse the author ID
		authorID, parseErr := uuid.Parse(authorIDStr)
		if parseErr != nil {
			respondWithError(w, http.StatusBadRequest, "Invalid author ID format")
			return
		}

		// Get chirps by specific author
		dbChirps, err = cfg.dbQueries.GetChirpsByAuthor(r.Context(), authorID)
		if err != nil {
			respondWithError(w, http.StatusInternalServerError, "Failed to retrieve chirps")
			fmt.Printf("Error getting chirps by author: %v\n", err)
			return
		}
	} else {
		// Get all chirps
		dbChirps, err = cfg.dbQueries.GetChirps(r.Context())
		if err != nil {
			respondWithError(w, http.StatusInternalServerError, "Failed to retrieve chirps")
			fmt.Printf("Error getting chirps: %v\n", err)
			return
		}
	}

	// Map database chirps to our main Chirp structs
	chirps := make([]Chirp, 0, len(dbChirps))
	for _, dbChirp := range dbChirps {
		chirps = append(chirps, Chirp{
			ID:        dbChirp.ID,
			CreatedAt: dbChirp.CreatedAt,
			UpdatedAt: dbChirp.UpdatedAt,
			Body:      dbChirp.Body,
			UserID:    dbChirp.UserID,
		})
	}

	// Sort the chirps based on the sort parameter
	switch sortParam {
	case "desc":
		// Sort in descending order (newest first)
		sort.Slice(chirps, func(i, j int) bool {
			return chirps[i].CreatedAt.After(chirps[j].CreatedAt)
		})
	default:
		// Default to ascending order (oldest first)
		sort.Slice(chirps, func(i, j int) bool {
			return chirps[i].CreatedAt.Before(chirps[j].CreatedAt)
		})
	}

	// Return the chirps as JSON
	respondWithJSON(w, http.StatusOK, chirps)
}

func (cfg *apiConfig) getChirpHandler(w http.ResponseWriter, r *http.Request) {
	chirpIDStr := r.PathValue("chirpID")
	if chirpIDStr == "" {
		respondWithError(w, http.StatusBadRequest, "Missing chirp ID")
		return
	}

	chirpID, err := uuid.Parse(chirpIDStr)
	if err != nil {
		respondWithError(w, http.StatusBadRequest, "Invalid chirp ID format")
		return
	}

	dbChirp, err := cfg.dbQueries.GetChirp(r.Context(), chirpID)
	if err != nil {
		if err == sql.ErrNoRows {
			respondWithError(w, http.StatusNotFound, "Chirp not found")
			return
		}
		respondWithError(w, http.StatusInternalServerError, "Failed to retrieve chirp")
		fmt.Printf("Error getting chirp: %v\n", err)
		return
	}

	chirp := Chirp{
		ID:        dbChirp.ID,
		CreatedAt: dbChirp.CreatedAt,
		UpdatedAt: dbChirp.UpdatedAt,
		Body:      dbChirp.Body,
		UserID:    dbChirp.UserID,
	}

	respondWithJSON(w, http.StatusOK, chirp)
}

func replaceProfaneWords(text string) string {
	words := strings.Split(text, " ")

	for i, word := range words {
		lowercaseWord := strings.ToLower(word)
		if profaneWords[lowercaseWord] {
			words[i] = "****"
		}
	}

	return strings.Join(words, " ")
}

func (cfg *apiConfig) middlewareMetricsInc(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cfg.fileserverHits.Add(1)
		next.ServeHTTP(w, r)
	})
}

func (cfg *apiConfig) adminMetricsHandler(w http.ResponseWriter, r *http.Request) {
	// Set the Content-Type header to HTML
	w.Header().Set("Content-Type", "text/html; charset=utf-8")

	// Write the status code (200 OK)
	w.WriteHeader(http.StatusOK)

	// Get the current hit count
	hits := cfg.fileserverHits.Load()

	// Create the HTML response with the hit count
	html := fmt.Sprintf(`<html>
  <body>
    <h1>Welcome, Chirpy Admin</h1>
    <p>Chirpy has been visited %d times!</p>
  </body>
</html>`, hits)

	// Write the HTML response
	w.Write([]byte(html))
}

func (cfg *apiConfig) resetHandler(w http.ResponseWriter, r *http.Request) {
	if cfg.platform != "dev" {
		w.WriteHeader(http.StatusForbidden)
		return
	}

	// Reset the counter to 0
	cfg.fileserverHits.Store(0)

	// Delete all users from the database
	err := cfg.dbQueries.DeleteAllUsers(r.Context())
	if err != nil {
		fmt.Printf("Error deleting users: %v\n", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	// Set the Content-Type header
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")

	// Write the status code (200 OK)
	w.WriteHeader(http.StatusOK)

	// Write a confirmation message
	w.Write([]byte("OK"))
}

func respondWithJSON(w http.ResponseWriter, code int, payload interface{}) {
	data, err := json.Marshal(payload)
	if err != nil {
		respondWithError(w, http.StatusInternalServerError, "Internal server errro")
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)

	w.Write(data)
}

func respondWithError(w http.ResponseWriter, code int, msg string) {
	respondWithJSON(w, code, errorResponse{Error: msg})
}

func (cfg *apiConfig) deleteChirpHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodDelete {
		respondWithError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}

	// Get the bearer token from the Authorization header
	tokenString, err := auth.GetBearerToken(r.Header)
	if err != nil {
		respondWithError(w, http.StatusUnauthorized, "Missing or invalid authorization header")
		return
	}

	// Validate the JWT token and get user ID
	userID, err := auth.ValidateJWT(tokenString, cfg.jwtSecret)
	if err != nil {
		respondWithError(w, http.StatusUnauthorized, "Invalid or expired token")
		return
	}

	// Get the chirp ID from the path parameter
	chirpIDStr := r.PathValue("chirpID")
	if chirpIDStr == "" {
		respondWithError(w, http.StatusBadRequest, "Missing chirp ID")
		return
	}

	// Parse the UUID
	chirpID, err := uuid.Parse(chirpIDStr)
	if err != nil {
		respondWithError(w, http.StatusBadRequest, "Invalid chirp ID format")
		return
	}

	// Get the chirp from the database to check ownership
	dbChirp, err := cfg.dbQueries.GetChirpByID(r.Context(), chirpID)
	if err != nil {
		if err == sql.ErrNoRows {
			respondWithError(w, http.StatusNotFound, "Chirp not found")
			return
		}
		respondWithError(w, http.StatusInternalServerError, "Failed to retrieve chirp")
		fmt.Printf("Error getting chirp: %v\n", err)
		return
	}

	// Check if the authenticated user is the author of the chirp
	if dbChirp.UserID != userID {
		respondWithError(w, http.StatusForbidden, "You are not authorized to delete this chirp")
		return
	}

	// Delete the chirp from the database
	err = cfg.dbQueries.DeleteChirp(r.Context(), chirpID)
	if err != nil {
		respondWithError(w, http.StatusInternalServerError, "Failed to delete chirp")
		fmt.Printf("Error deleting chirp: %v\n", err)
		return
	}

	// Return 204 No Content
	w.WriteHeader(http.StatusNoContent)
}

func (cfg *apiConfig) polkaWebhookHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		respondWithError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}

	// Get the API key from the Authorization header
	apiKey, err := auth.GetAPIKey(r.Header)
	if err != nil {
		respondWithError(w, http.StatusUnauthorized, "Missing or invalid authorization header")
		return
	}

	// Check if the API key matches the one from .env
	if apiKey != cfg.polkaKey {
		respondWithError(w, http.StatusUnauthorized, "Invalid API key")
		return
	}

	// Parse request body
	var req webhookRequest
	err = json.NewDecoder(r.Body).Decode(&req)
	if err != nil {
		respondWithError(w, http.StatusBadRequest, "Invalid request body")
		return
	}

	// If event is not "user.upgraded", ignore with 204
	if req.Event != "user.upgraded" {
		w.WriteHeader(http.StatusNoContent)
		return
	}

	// Parse the user ID from the request
	userID, err := uuid.Parse(req.Data.UserID)
	if err != nil {
		respondWithError(w, http.StatusBadRequest, "Invalid user ID format")
		return
	}

	// Upgrade the user to Chirpy Red
	err = cfg.dbQueries.UpgradeToChirpyRed(r.Context(), userID)
	if err != nil {
		if err == sql.ErrNoRows {
			respondWithError(w, http.StatusNotFound, "User not found")
			return
		}
		respondWithError(w, http.StatusInternalServerError, "Failed to upgrade user")
		fmt.Printf("Error upgrading user: %v\n", err)
		return
	}

	// Return 204 No Content on success
	w.WriteHeader(http.StatusNoContent)
}
