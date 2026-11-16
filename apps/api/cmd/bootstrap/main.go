package main

import (
	"bufio"
	"context"
	"flag"
	"fmt"
	"os"
	"strings"
	"syscall"
	"time"

	"github.com/google/uuid"
	"github.com/kelvin/kelvin/apps/api/internal/auth"
	"github.com/kelvin/kelvin/apps/api/internal/database"
	"go.uber.org/zap"
	"golang.org/x/term"
)

func main() {
	var (
		tenantName  string
		tenantSlug  string
		adminEmail  string
		adminName   string
		adminRole   string
		dbURL       string
		sslRootCert string
		passFlag    string
	)

	flag.StringVar(&tenantName, "tenant-name", "Kelvin Security Corp", "Display name of initial tenant organization")
	flag.StringVar(&tenantSlug, "tenant-slug", "kelvin-corp", "URL slug of initial tenant organization")
	flag.StringVar(&adminEmail, "admin-email", "owner@eozka.com", "Email of the initial administrator")
	flag.StringVar(&adminName, "admin-name", "Project Owner", "Full display name of the initial administrator")
	flag.StringVar(&adminRole, "admin-role", "PLATFORM_ADMIN", "Role for administrator (PLATFORM_ADMIN or TENANT_ADMIN)")
	flag.StringVar(&dbURL, "database-url", "", "PostgreSQL database connection URL (falls back to KELVIN_DATABASE_URL)")
	flag.StringVar(&sslRootCert, "ssl-root-cert", "", "Path to SSL CA certificate (falls back to SUPABASE_CA_CERT_PATH)")
	flag.StringVar(&passFlag, "password", "", "Initial admin password (or read securely from KELVIN_BOOTSTRAP_PASSWORD or stdin)")
	flag.Parse()

	if dbURL == "" {
		dbURL = os.Getenv("KELVIN_DATABASE_URL")
	}
	if dbURL == "" {
		fmt.Fprintln(os.Stderr, "Error: database URL must be provided via --database-url or KELVIN_DATABASE_URL environment variable")
		os.Exit(1)
	}

	if sslRootCert == "" {
		sslRootCert = os.Getenv("SUPABASE_CA_CERT_PATH")
	}

	adminEmail = strings.ToLower(strings.TrimSpace(adminEmail))
	if adminEmail == "" || !strings.Contains(adminEmail, "@") {
		fmt.Fprintln(os.Stderr, "Error: a valid admin email must be specified")
		os.Exit(1)
	}

	role := auth.Role(strings.ToUpper(strings.TrimSpace(adminRole)))
	if role != auth.RolePlatformAdmin && role != auth.RoleTenantAdmin {
		fmt.Fprintf(os.Stderr, "Error: invalid admin role %q; must be PLATFORM_ADMIN or TENANT_ADMIN\n", adminRole)
		os.Exit(1)
	}

	password := passFlag
	if password == "" {
		password = os.Getenv("KELVIN_BOOTSTRAP_PASSWORD")
	}

	if password == "" {
		// If connected to interactive terminal, prompt without echo
		if term.IsTerminal(int(syscall.Stdin)) {
			fmt.Printf("Enter password for administrator %s: ", adminEmail)
			passBytes, err := term.ReadPassword(int(syscall.Stdin))
			fmt.Println()
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error reading password: %v\n", err)
				os.Exit(1)
			}
			password = string(passBytes)
		} else {
			// Read from stdin pipe
			reader := bufio.NewReader(os.Stdin)
			line, err := reader.ReadString('\n')
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error reading password from stdin: %v\n", err)
				os.Exit(1)
			}
			password = strings.TrimRight(line, "\r\n")
		}
	}

	password = strings.TrimSpace(password)
	if len(password) < 8 {
		fmt.Fprintln(os.Stderr, "Error: password must be at least 8 characters long")
		os.Exit(1)
	}
	if len(password) > 72 {
		fmt.Fprintln(os.Stderr, "Error: password exceeds bcrypt maximum length of 72 characters")
		os.Exit(1)
	}

	passwordHash, err := auth.HashPassword(password)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error hashing password: %v\n", err)
		os.Exit(1)
	}

	poolCfg := database.DefaultPoolConfig()
	poolCfg.MaxConns = 2
	poolCfg.MinConns = 1
	if sslRootCert != "" {
		poolCfg.SSLRootCert = sslRootCert
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	log, _ := zap.NewProduction()
	pool, err := database.NewPool(ctx, dbURL, poolCfg, log)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Database connection failed: %v\n", err)
		os.Exit(1)
	}
	defer pool.Close()

	repo := auth.NewPostgresRepository(pool)

	tenantID := uuid.New()
	userID := uuid.New()

	tenant := &auth.Tenant{
		ID:        tenantID,
		Name:      tenantName,
		Slug:      tenantSlug,
		Status:    "ACTIVE",
		CreatedAt: time.Now().UTC(),
		UpdatedAt: time.Now().UTC(),
	}

	admin := &auth.User{
		ID:           userID,
		TenantID:     tenantID,
		Email:        adminEmail,
		DisplayName:  adminName,
		PasswordHash: passwordHash,
		Role:         role,
		IsActive:     true,
		CreatedAt:    time.Now().UTC(),
		UpdatedAt:    time.Now().UTC(),
	}

	if err := repo.CreateTenantAndAdmin(ctx, tenant, admin); err != nil {
		fmt.Fprintf(os.Stderr, "Bootstrap failed: %v\n", err)
		os.Exit(1)
	}

	fmt.Println("=========================================================")
	fmt.Println("  KELVIN Bootstrap Succeeded")
	fmt.Println("=========================================================")
	fmt.Printf("Tenant ID:        %s\n", tenant.ID.String())
	fmt.Printf("Tenant Name:      %s\n", tenant.Name)
	fmt.Printf("Tenant Slug:      %s\n", tenant.Slug)
	fmt.Printf("Admin User ID:    %s\n", admin.ID.String())
	fmt.Printf("Admin Email:      %s\n", admin.Email)
	fmt.Printf("Admin Name:       %s\n", admin.DisplayName)
	fmt.Printf("Admin Role:       %s\n", admin.Role)
	fmt.Println("=========================================================")
	fmt.Println("Administrator account is ready for production login.")
}
