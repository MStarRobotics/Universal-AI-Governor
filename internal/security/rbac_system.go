package security

import (
	"fmt"
	"sync"
	"time"

	"github.com/universal-ai-governor/internal/logging"
)

// RBACSystem implements Role-Based Access Control with JIT elevation
type RBACSystem struct {
	logger          logging.Logger
	roles           map[string]*Role
	users           map[string]*User
	sessions        map[string]*Session
	elevationTokens map[string]*ElevationToken
	mutex           sync.RWMutex
}

// Role defines a security role with permissions and constraints
type Role struct {
	Name            string                 `json:"name"`
	Description     string                 `json:"description"`
	Permissions     []string               `json:"permissions"`
	Resources       []string               `json:"resources"`
	Constraints     map[string]interface{} `json:"constraints"`
	MaxSessionTime  time.Duration          `json:"max_session_time"`
	RequiresMFA     bool                   `json:"requires_mfa"`
	ElevationLevel  int                    `json:"elevation_level"`
	CreatedAt       time.Time              `json:"created_at"`
	UpdatedAt       time.Time              `json:"updated_at"`
}

// User represents a system user with assigned roles
type User struct {
	ID              string                 `json:"id"`
	Username        string                 `json:"username"`
	Email           string                 `json:"email"`
	Roles           []string               `json:"roles"`
	MFAEnabled      bool                   `json:"mfa_enabled"`
	MFASecret       string                 `json:"mfa_secret,omitempty"`
	LastLogin       time.Time              `json:"last_login"`
	FailedAttempts  int                    `json:"failed_attempts"`
	LockedUntil     time.Time              `json:"locked_until"`
	Metadata        map[string]interface{} `json:"metadata"`
	CreatedAt       time.Time              `json:"created_at"`
	UpdatedAt       time.Time              `json:"updated_at"`
}

// Session represents an active user session
type Session struct {
	ID              string                 `json:"id"`
	UserID          string                 `json:"user_id"`
	Username        string                 `json:"username"`
	Roles           []string               `json:"roles"`
	Permissions     []string               `json:"permissions"`
	ElevatedUntil   time.Time              `json:"elevated_until"`
	CreatedAt       time.Time              `json:"created_at"`
	ExpiresAt       time.Time              `json:"expires_at"`
	LastActivity    time.Time              `json:"last_activity"`
	IPAddress       string                 `json:"ip_address"`
	UserAgent       string                 `json:"user_agent"`
	MFAVerified     bool                   `json:"mfa_verified"`
	Metadata        map[string]interface{} `json:"metadata"`
}

// ElevationToken represents a Just-In-Time elevation token
type ElevationToken struct {
	Token           string    `json:"token"`
	UserID          string    `json:"user_id"`
	SessionID       string    `json:"session_id"`
	RequiredRole    string    `json:"required_role"`
	Operation       string    `json:"operation"`
	CreatedAt       time.Time `json:"created_at"`
	ExpiresAt       time.Time `json:"expires_at"`
	Used            bool      `json:"used"`
	UsedAt          time.Time `json:"used_at"`
	ApprovalCount   int       `json:"approval_count"`
	RequiredApprovals int     `json:"required_approvals"`
	Approvers       []string  `json:"approvers"`
}

// MultiPartyApproval represents a multi-party authorization request
type MultiPartyApproval struct {
	ID              string                 `json:"id"`
	Operation       string                 `json:"operation"`
	RequestedBy     string                 `json:"requested_by"`
	RequiredSigners int                    `json:"required_signers"`
	Signatures      []ApprovalSignature    `json:"signatures"`
	Metadata        map[string]interface{} `json:"metadata"`
	CreatedAt       time.Time              `json:"created_at"`
	ExpiresAt       time.Time              `json:"expires_at"`
	Status          string                 `json:"status"`
}

// ApprovalSignature represents a single approval signature
type ApprovalSignature struct {
	SignerID    string    `json:"signer_id"`
	Signature   string    `json:"signature"`
	SignedAt    time.Time `json:"signed_at"`
	IPAddress   string    `json:"ip_address"`
	UserAgent   string    `json:"user_agent"`
}

// NewRBACSystem creates a new RBAC system
func NewRBACSystem(logger logging.Logger) *RBACSystem {
	rbac := &RBACSystem{
		logger:          logger,
		roles:           make(map[string]*Role),
		users:           make(map[string]*User),
		sessions:        make(map[string]*Session),
		elevationTokens: make(map[string]*ElevationToken),
	}

	// Initialize default roles
	rbac.initializeDefaultRoles()

	logger.Info("RBAC system initialized")
	return rbac
}

// initializeDefaultRoles creates the default system roles
func (rbac *RBACSystem) initializeDefaultRoles() {
	defaultRoles := []*Role{
		{
			Name:        "super_admin",
			Description: "Super Administrator with full system access",
			Permissions: []string{"*"},
			Resources:   []string{"*"},
			Constraints: map[string]interface{}{
				"ip_whitelist": []string{"127.0.0.1", "::1"},
				"time_window":  "business_hours",
			},
			MaxSessionTime: 4 * time.Hour,
			RequiresMFA:    true,
			ElevationLevel: 5,
			CreatedAt:      time.Now(),
			UpdatedAt:      time.Now(),
		},
		{
			Name:        "security_admin",
			Description: "Security Administrator for policy and threat management",
			Permissions: []string{
				"policy:read", "policy:write", "policy:delete",
				"threat:read", "threat:write", "threat:investigate",
				"audit:read", "user:read",
			},
			Resources: []string{
				"policies/*", "threats/*", "audit/*", "users/*",
			},
			MaxSessionTime: 8 * time.Hour,
			RequiresMFA:    true,
			ElevationLevel: 4,
			CreatedAt:      time.Now(),
			UpdatedAt:      time.Now(),
		},
		{
			Name:        "system_admin",
			Description: "System Administrator for service configuration",
			Permissions: []string{
				"service:read", "service:write", "service:restart",
				"config:read", "config:write", "monitoring:read",
			},
			Resources: []string{
				"services/*", "configs/*", "monitoring/*",
			},
			MaxSessionTime: 8 * time.Hour,
			RequiresMFA:    true,
			ElevationLevel: 3,
			CreatedAt:      time.Now(),
			UpdatedAt:      time.Now(),
		},
		{
			Name:        "audit_admin",
			Description: "Audit Administrator for compliance and reporting",
			Permissions: []string{
				"audit:read", "audit:export", "compliance:read",
				"report:generate", "log:read",
			},
			Resources: []string{
				"audit/*", "compliance/*", "reports/*", "logs/*",
			},
			MaxSessionTime: 12 * time.Hour,
			RequiresMFA:    false,
			ElevationLevel: 2,
			CreatedAt:      time.Now(),
			UpdatedAt:      time.Now(),
		},
		{
			Name:        "operator",
			Description: "System Operator with basic operational access",
			Permissions: []string{
				"service:read", "monitoring:read", "health:read",
				"metrics:read", "status:read",
			},
			Resources: []string{
				"services/status", "monitoring/*", "health/*", "metrics/*",
			},
			MaxSessionTime: 12 * time.Hour,
			RequiresMFA:    false,
			ElevationLevel: 1,
			CreatedAt:      time.Now(),
			UpdatedAt:      time.Now(),
		},
		{
			Name:        "end_user",
			Description: "End User with API access only",
			Permissions: []string{
				"api:read", "api:write", "governance:request",
			},
			Resources: []string{
				"api/v1/governance/*",
			},
			MaxSessionTime: 24 * time.Hour,
			RequiresMFA:    false,
			ElevationLevel: 0,
			CreatedAt:      time.Now(),
			UpdatedAt:      time.Now(),
		},
	}

	for _, role := range defaultRoles {
		rbac.roles[role.Name] = role
	}

	rbac.logger.Info("Default roles initialized", "count", len(defaultRoles))
}

// CreateUser creates a new user with specified roles
func (rbac *RBACSystem) CreateUser(username, email string, roles []string) (*User, error) {
	rbac.mutex.Lock()
	defer rbac.mutex.Unlock()

	// Validate roles exist
	for _, roleName := range roles {
		if _, exists := rbac.roles[roleName]; !exists {
			return nil, fmt.Errorf("role %s does not exist", roleName)
		}
	}

	userID := generateSecureID()
	user := &User{
		ID:             userID,
		Username:       username,
		Email:          email,
		Roles:          roles,
		MFAEnabled:     false,
		LastLogin:      time.Time{},
		FailedAttempts: 0,
		LockedUntil:    time.Time{},
		Metadata:       make(map[string]interface{}),
		CreatedAt:      time.Now(),
		UpdatedAt:      time.Now(),
	}

	rbac.users[userID] = user

	rbac.logger.Info("User created",
		"user_id", userID,
		"username", username,
		"roles", roles)

	return user, nil
}

// AuthenticateUser authenticates a user and creates a session
func (rbac *RBACSystem) AuthenticateUser(username, password string, mfaToken string, clientInfo map[string]string) (*Session, error) {
	rbac.mutex.Lock()
	defer rbac.mutex.Unlock()

	// Find user by username
	var user *User
	for _, u := range rbac.users {
		if u.Username == username {
			user = u
			break
		}
	}

	if user == nil {
		rbac.logger.Warn("Authentication failed - user not found", "username", username)
		return nil, fmt.Errorf("authentication failed")
	}

	// Check if user is locked
	if time.Now().Before(user.LockedUntil) {
		rbac.logger.Warn("Authentication failed - user locked",
			"username", username,
			"locked_until", user.LockedUntil)
		return nil, fmt.Errorf("user account is locked")
	}

	// Verify password (simplified - in production use proper password verification)
	if !rbac.verifyPassword(user, password) {
		user.FailedAttempts++
		if user.FailedAttempts >= 5 {
			user.LockedUntil = time.Now().Add(30 * time.Minute)
			rbac.logger.Warn("User locked due to failed attempts",
				"username", username,
				"failed_attempts", user.FailedAttempts)
		}
		return nil, fmt.Errorf("authentication failed")
	}

	// Verify MFA if enabled
	if user.MFAEnabled {
		if !rbac.verifyMFA(user, mfaToken) {
			rbac.logger.Warn("MFA verification failed", "username", username)
			return nil, fmt.Errorf("MFA verification failed")
		}
	}

	// Reset failed attempts on successful authentication
	user.FailedAttempts = 0
	user.LastLogin = time.Now()
	user.UpdatedAt = time.Now()

	// Create session
	session := rbac.createSession(user, clientInfo)

	rbac.logger.Info("User authenticated successfully",
		"username", username,
		"session_id", session.ID,
		"roles", user.Roles)

	return session, nil
}

// createSession creates a new user session
func (rbac *RBACSystem) createSession(user *User, clientInfo map[string]string) *Session {
	sessionID := generateSecureID()

	// Calculate session expiration based on roles
	maxSessionTime := 24 * time.Hour
	for _, roleName := range user.Roles {
		if role, exists := rbac.roles[roleName]; exists {
			if role.MaxSessionTime < maxSessionTime {
				maxSessionTime = role.MaxSessionTime
			}
		}
	}

	// Collect all permissions from user roles
	permissions := rbac.getUserPermissions(user)

	session := &Session{
		ID:           sessionID,
		UserID:       user.ID,
		Username:     user.Username,
		Roles:        user.Roles,
		Permissions:  permissions,
		CreatedAt:    time.Now(),
		ExpiresAt:    time.Now().Add(maxSessionTime),
		LastActivity: time.Now(),
		IPAddress:    clientInfo["ip_address"],
		UserAgent:    clientInfo["user_agent"],
		MFAVerified:  user.MFAEnabled,
		Metadata:     make(map[string]interface{}),
	}

	rbac.sessions[sessionID] = session
	return session
}

// getUserPermissions collects all permissions for a user based on their roles
func (rbac *RBACSystem) getUserPermissions(user *User) []string {
	permissionSet := make(map[string]bool)

	for _, roleName := range user.Roles {
		if role, exists := rbac.roles[roleName]; exists {
			for _, permission := range role.Permissions {
				permissionSet[permission] = true
			}
		}
	}

	permissions := make([]string, 0, len(permissionSet))
	for permission := range permissionSet {
		permissions = append(permissions, permission)
	}

	return permissions
}

// CheckPermission verifies if a session has the required permission
func (rbac *RBACSystem) CheckPermission(sessionID, permission, resource string) error {
	rbac.mutex.RLock()
	defer rbac.mutex.RUnlock()

	session, exists := rbac.sessions[sessionID]
	if !exists {
		return fmt.Errorf("session not found")
	}

	// Check session expiration
	if time.Now().After(session.ExpiresAt) {
		delete(rbac.sessions, sessionID)
		return fmt.Errorf("session expired")
	}

	// Update last activity
	session.LastActivity = time.Now()

	// Check if user has wildcard permission
	for _, userPerm := range session.Permissions {
		if userPerm == "*" {
			return nil
		}
	}

	// Check specific permission
	for _, userPerm := range session.Permissions {
		if userPerm == permission {
			// Check resource access
			if rbac.checkResourceAccess(session, resource) {
				return nil
			}
		}
	}

	rbac.logger.Warn("Permission denied",
		"session_id", sessionID,
		"username", session.Username,
		"permission", permission,
		"resource", resource)

	return fmt.Errorf("permission denied")
}

// checkResourceAccess verifies if the session can access the specified resource
func (rbac *RBACSystem) checkResourceAccess(session *Session, resource string) bool {
	for _, roleName := range session.Roles {
		if role, exists := rbac.roles[roleName]; exists {
			for _, allowedResource := range role.Resources {
				if allowedResource == "*" || allowedResource == resource {
					return true
				}
				// Check wildcard patterns
				if rbac.matchResourcePattern(allowedResource, resource) {
					return true
				}
			}
		}
	}
	return false
}

// matchResourcePattern checks if a resource matches a pattern
func (rbac *RBACSystem) matchResourcePattern(pattern, resource string) bool {
	// Simple wildcard matching (in production, use proper pattern matching)
	if len(pattern) > 0 && pattern[len(pattern)-1] == '*' {
		prefix := pattern[:len(pattern)-1]
		return len(resource) >= len(prefix) && resource[:len(prefix)] == prefix
	}
	return pattern == resource
}

// RequestElevation requests Just-In-Time privilege elevation
func (rbac *RBACSystem) RequestElevation(sessionID, operation, requiredRole string) (*ElevationToken, error) {
	rbac.mutex.Lock()
	defer rbac.mutex.Unlock()

	session, exists := rbac.sessions[sessionID]
	if !exists {
		return nil, fmt.Errorf("session not found")
	}

	// Check if user already has the required role
	for _, userRole := range session.Roles {
		if userRole == requiredRole {
			return nil, fmt.Errorf("user already has required role")
		}
	}

	// Generate elevation token
	tokenID := generateSecureID()
	token := &ElevationToken{
		Token:             tokenID,
		UserID:            session.UserID,
		SessionID:         sessionID,
		RequiredRole:      requiredRole,
		Operation:         operation,
		CreatedAt:         time.Now(),
		ExpiresAt:         time.Now().Add(5 * time.Minute), // Short-lived token
		Used:              false,
		ApprovalCount:     0,
		RequiredApprovals: rbac.getRequiredApprovals(requiredRole),
		Approvers:         make([]string, 0),
	}

	rbac.elevationTokens[tokenID] = token

	rbac.logger.Info("Elevation token requested",
		"session_id", sessionID,
		"username", session.Username,
		"required_role", requiredRole,
		"operation", operation,
		"token", tokenID)

	return token, nil
}

// getRequiredApprovals determines how many approvals are needed for elevation
func (rbac *RBACSystem) getRequiredApprovals(roleName string) int {
	role, exists := rbac.roles[roleName]
	if !exists {
		return 1
	}

	// Higher elevation levels require more approvals
	switch role.ElevationLevel {
	case 5: // super_admin
		return 2
	case 4: // security_admin
		return 2
	case 3: // system_admin
		return 1
	default:
		return 1
	}
}

// ApproveElevation approves an elevation request
func (rbac *RBACSystem) ApproveElevation(tokenID, approverSessionID string) error {
	rbac.mutex.Lock()
	defer rbac.mutex.Unlock()

	token, exists := rbac.elevationTokens[tokenID]
	if !exists {
		return fmt.Errorf("elevation token not found")
	}

	if token.Used {
		return fmt.Errorf("elevation token already used")
	}

	if time.Now().After(token.ExpiresAt) {
		delete(rbac.elevationTokens, tokenID)
		return fmt.Errorf("elevation token expired")
	}

	approverSession, exists := rbac.sessions[approverSessionID]
	if !exists {
		return fmt.Errorf("approver session not found")
	}

	// Check if approver has sufficient privileges
	if !rbac.canApproveElevation(approverSession, token.RequiredRole) {
		return fmt.Errorf("insufficient privileges to approve elevation")
	}

	// Check if approver already approved
	for _, approver := range token.Approvers {
		if approver == approverSession.UserID {
			return fmt.Errorf("approver already approved this request")
		}
	}

	// Add approval
	token.Approvers = append(token.Approvers, approverSession.UserID)
	token.ApprovalCount++

	rbac.logger.Info("Elevation approved",
		"token", tokenID,
		"approver", approverSession.Username,
		"approval_count", token.ApprovalCount,
		"required_approvals", token.RequiredApprovals)

	return nil
}

// canApproveElevation checks if a user can approve elevation to a specific role
func (rbac *RBACSystem) canApproveElevation(session *Session, targetRole string) bool {
	targetRoleObj, exists := rbac.roles[targetRole]
	if !exists {
		return false
	}

	// Check if any of the user's roles have higher or equal elevation level
	for _, userRole := range session.Roles {
		if role, exists := rbac.roles[userRole]; exists {
			if role.ElevationLevel >= targetRoleObj.ElevationLevel {
				return true
			}
		}
	}

	return false
}

// UseElevationToken uses an elevation token to temporarily elevate privileges
func (rbac *RBACSystem) UseElevationToken(tokenID string) error {
	rbac.mutex.Lock()
	defer rbac.mutex.Unlock()

	token, exists := rbac.elevationTokens[tokenID]
	if !exists {
		return fmt.Errorf("elevation token not found")
	}

	if token.Used {
		return fmt.Errorf("elevation token already used")
	}

	if time.Now().After(token.ExpiresAt) {
		delete(rbac.elevationTokens, tokenID)
		return fmt.Errorf("elevation token expired")
	}

	if token.ApprovalCount < token.RequiredApprovals {
		return fmt.Errorf("insufficient approvals: %d/%d", token.ApprovalCount, token.RequiredApprovals)
	}

	// Mark token as used
	token.Used = true
	token.UsedAt = time.Now()

	// Elevate session privileges temporarily
	session, exists := rbac.sessions[token.SessionID]
	if !exists {
		return fmt.Errorf("session not found")
	}

	session.ElevatedUntil = time.Now().Add(15 * time.Minute) // 15-minute elevation window
	session.Roles = append(session.Roles, token.RequiredRole)
	session.Permissions = rbac.getUserPermissions(&User{Roles: session.Roles})

	rbac.logger.Info("Privileges elevated",
		"session_id", token.SessionID,
		"username", session.Username,
		"elevated_role", token.RequiredRole,
		"elevated_until", session.ElevatedUntil)

	return nil
}

// Helper functions

func (rbac *RBACSystem) verifyPassword(user *User, password string) bool {
	// In production, this would verify against a properly hashed password
	// For demonstration, we'll simulate password verification
	return len(password) >= 8
}

func (rbac *RBACSystem) verifyMFA(user *User, token string) bool {
	// In production, this would verify TOTP token against user's MFA secret
	// For demonstration, we'll simulate MFA verification
	return len(token) == 6
}
