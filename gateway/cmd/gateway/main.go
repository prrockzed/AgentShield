// @title           AgentShield API
// @version         1.0
// @description     Runtime security platform for autonomous AI agents.
// @host            localhost:8080
// @BasePath        /api
// @securityDefinitions.apikey BearerAuth
// @in header
// @name Authorization
package main

import (
	"crypto/tls"
	"database/sql"
	"fmt"
	"net/http"
	"os"

	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
	"github.com/golang-migrate/migrate/v4"
	"github.com/golang-migrate/migrate/v4/database/postgres"
	"github.com/golang-migrate/migrate/v4/source/iofs"
	_ "github.com/lib/pq"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	swaggerfiles "github.com/swaggo/files"
	ginswagger "github.com/swaggo/gin-swagger"
	"golang.org/x/crypto/bcrypt"

	"github.com/prrockzed/agentshield/gateway/db"
	_ "github.com/prrockzed/agentshield/gateway/docs"
	"github.com/prrockzed/agentshield/gateway/internal/handlers"
	"github.com/prrockzed/agentshield/gateway/internal/metrics"
	"github.com/prrockzed/agentshield/gateway/internal/middleware"
	natscons "github.com/prrockzed/agentshield/gateway/internal/nats"
	agentshieldtls "github.com/prrockzed/agentshield/gateway/internal/tls"
	"github.com/prrockzed/agentshield/gateway/internal/ws"
)

func main() {
	// --- Structured logging ---
	zerolog.TimeFieldFormat = zerolog.TimeFormatUnix
	if os.Getenv("LOG_FORMAT") == "text" {
		log.Logger = log.Output(zerolog.ConsoleWriter{Out: os.Stderr})
	}
	zerolog.SetGlobalLevel(zerolog.InfoLevel)
	if os.Getenv("LOG_LEVEL") == "debug" {
		zerolog.SetGlobalLevel(zerolog.DebugLevel)
	}

	// --- Database ---
	dsn := fmt.Sprintf(
		"host=%s port=%s dbname=%s user=%s password=%s sslmode=disable",
		getEnv("POSTGRES_HOST", "localhost"),
		getEnv("POSTGRES_PORT", "5432"),
		getEnv("POSTGRES_DB", "agentshield"),
		getEnv("POSTGRES_USER", "agentshield"),
		getEnv("POSTGRES_PASSWORD", "agentshield"),
	)

	sqlDB, err := sql.Open("postgres", dsn)
	if err != nil {
		log.Fatal().Err(err).Msg("failed to open DB")
	}
	defer sqlDB.Close()

	if err := sqlDB.Ping(); err != nil {
		log.Fatal().Err(err).Msg("failed to ping DB")
	}
	log.Info().Msg("connected to postgres")

	// --- Migrations ---
	srcDriver, err := iofs.New(db.Migrations, "migrations")
	if err != nil {
		log.Fatal().Err(err).Msg("failed to load migration source")
	}

	dbDriver, err := postgres.WithInstance(sqlDB, &postgres.Config{})
	if err != nil {
		log.Fatal().Err(err).Msg("failed to create migrate driver")
	}

	m, err := migrate.NewWithInstance("iofs", srcDriver, "postgres", dbDriver)
	if err != nil {
		log.Fatal().Err(err).Msg("failed to create migrator")
	}

	if err := m.Up(); err != nil && err != migrate.ErrNoChange {
		log.Fatal().Err(err).Msg("migration failed")
	}
	log.Info().Msg("migrations applied")

	// --- Seed admin user ---
	seedAdmin(sqlDB)

	// --- Metrics ---
	metrics.Register()

	// --- WebSocket Hub ---
	hub := ws.NewHub()

	// --- NATS Consumer ---
	consumer, err := natscons.New(getEnv("NATS_URL", "nats://nats:4222"), sqlDB, hub)
	if err != nil {
		log.Fatal().Err(err).Msg("nats connection failed")
	}
	consumer.Start()

	// --- HTTP ---
	port := getEnv("GATEWAY_PORT", "8080")
	runtimeURL := getEnv("RUNTIME_URL", "http://runtime:8000")
	securityEngineURL := getEnv("SECURITY_ENGINE_URL", "http://security-engine:8001")
	r := gin.Default()

	r.Use(middleware.RequestID())
	r.Use(cors.New(cors.Config{
		AllowOrigins:     []string{getEnv("CORS_ALLOWED_ORIGIN", "http://localhost:3000")},
		AllowMethods:     []string{"GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"},
		AllowHeaders:     []string{"Origin", "Content-Type", "Authorization", "X-Request-ID"},
		ExposeHeaders:    []string{"X-Request-ID"},
		AllowCredentials: true,
	}))

	r.GET("/health", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"status": "ok", "service": "gateway"})
	})

	// Prometheus metrics — public, no auth
	r.GET("/metrics", gin.WrapH(promhttp.Handler()))

	// Swagger UI — public, no auth
	r.GET("/api/docs/*any", ginswagger.WrapHandler(swaggerfiles.Handler))

	h := handlers.NewHandler(sqlDB, hub, runtimeURL, securityEngineURL)

	// Public — no auth required
	authGroup := r.Group("/api/auth")
	{
		authGroup.POST("/login", h.Login)
		authGroup.POST("/refresh", h.Refresh)
	}

	// Protected — JWT required
	api := r.Group("/api", middleware.RequireAuth())
	{
		api.GET("/agents", h.ListAgents)
		api.GET("/models", h.ListModels)
		api.POST("/runs", middleware.RateLimitRuns(), h.SubmitRun)
		api.GET("/runs", h.ListRuns)
		api.GET("/runs/:id", h.GetRun)
		api.GET("/runs/:id/behavior", h.GetRunBehavior)
		api.GET("/runs/:id/hallucination", h.GetRunHallucination)
		api.POST("/events", h.CreateEvent)
		api.GET("/events", h.ListEvents)

		intel := api.Group("/intelligence")
		{
			intel.GET("/signatures", h.ListSignatures)
			intel.POST("/signatures", h.CreateSignature)
			intel.PATCH("/signatures/:id", h.ToggleSignature)
			intel.DELETE("/signatures/:id", h.DeleteSignature)
			intel.GET("/stats", h.GetIntelligenceStats)
			intel.GET("/yara-rules", h.ListYaraRules)
			intel.POST("/yara-rules", h.CreateYaraRule)
			intel.PATCH("/yara-rules/:id", h.ToggleYaraRule)
			intel.DELETE("/yara-rules/:id", h.DeleteYaraRule)
		}

		policies := api.Group("/policies")
		{
			policies.GET("/shell", h.ListShellRules)
			policies.POST("/shell", h.CreateShellRule)
			policies.PATCH("/shell/:id", h.ToggleShellRule)
			policies.DELETE("/shell/:id", h.DeleteShellRule)
			policies.GET("/dlp", h.ListDlpPolicies)
			policies.POST("/dlp", h.CreateDlpPolicy)
			policies.PATCH("/dlp/:id", h.ToggleDlpPolicy)
			policies.DELETE("/dlp/:id", h.DeleteDlpPolicy)
			policies.GET("/network", h.GetNetworkPolicies)
			policies.POST("/network/allow", h.CreateNetworkPolicy)
			policies.PATCH("/network/:id", h.ToggleNetworkPolicy)
			policies.DELETE("/network/:id", h.DeleteNetworkPolicy)
			policies.GET("/filesystem", h.GetFilesystemPolicies)
			policies.POST("/filesystem", h.CreateFilesystemPolicy)
			policies.PATCH("/filesystem/:id", h.ToggleFilesystemPolicy)
			policies.DELETE("/filesystem/:id", h.DeleteFilesystemPolicy)
		}

		settings := api.Group("/settings")
		{
			settings.GET("/security", h.GetSecuritySettings)
			settings.PUT("/security", h.UpdateSecuritySettings)
		}

		redteam := api.Group("/redteam")
		{
			redteam.POST("/run", h.TriggerRedteamRun)
			redteam.GET("/results", h.ListRedteamRuns)
			redteam.GET("/results/:id", h.GetRedteamRun)
		}

		// Admin-only: user management
		users := api.Group("/users", middleware.RequireAdmin())
		{
			users.POST("", h.CreateUser)
			users.GET("", h.ListUsers)
			users.DELETE("/:id", h.DeleteUser)
		}
	}

	// WebSocket — token via ?token= query param
	r.GET("/ws/events", h.WebSocketEvents)

	// --- TLS (optional) ---
	tlsEnabled := os.Getenv("TLS_ENABLED") == "true"
	if tlsEnabled {
		var tlsCfg *tls.Config
		if domain := os.Getenv("ACME_DOMAIN"); domain != "" {
			tlsCfg = agentshieldtls.AcmeTLSConfig(domain)
			log.Info().Str("domain", domain).Msg("TLS: using Let's Encrypt (ACME)")
		} else {
			tlsCfg, err = agentshieldtls.GenerateSelfSigned()
			if err != nil {
				log.Fatal().Err(err).Msg("TLS: failed to generate self-signed certificate")
			}
			log.Info().Msg("TLS: using self-signed certificate")
		}
		srv := &http.Server{
			Addr:      ":8443",
			Handler:   r,
			TLSConfig: tlsCfg,
		}
		go func() {
			log.Info().Str("addr", ":8443").Msg("gateway TLS listening")
			if err := srv.ListenAndServeTLS("", ""); err != nil && err != http.ErrServerClosed {
				log.Error().Err(err).Msg("TLS server error")
			}
		}()
	}

	log.Info().Str("addr", ":"+port).Msg("gateway listening")
	if err := r.Run(":" + port); err != nil {
		log.Fatal().Err(err).Msg("server error")
	}
}

func seedAdmin(sqlDB *sql.DB) {
	email := os.Getenv("ADMIN_EMAIL")
	password := os.Getenv("ADMIN_PASSWORD")
	if email == "" || password == "" {
		log.Info().Msg("seed: ADMIN_EMAIL/ADMIN_PASSWORD not set — skipping")
		return
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		log.Fatal().Err(err).Msg("seed: bcrypt failed")
	}
	if _, err = sqlDB.Exec(
		`INSERT INTO users (email, password_hash, role) VALUES ($1, $2, 'admin') ON CONFLICT (email) DO NOTHING`,
		email, string(hash),
	); err != nil {
		log.Fatal().Err(err).Msg("seed: insert failed")
	}
	log.Info().Str("email", email).Msg("seed: admin ready")
}

func getEnv(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
