# Axiom Server - SuperNanny 3-Tier Architecture

## Overview

The **Axiom Server** is the core middleware component of the SuperNanny cybersecurity solution, implementing a secure 3-tier architecture that acts as an intermediary between user workstations and the PostgreSQL database. Built in Rust using the Axum web framework, it ensures secure communication, authentication, and authorization while preventing direct database access from client systems.

## Architecture Role

```
┌─────────────────┐    HTTPS/TLS    ┌─────────────────┐    Connection Pool    ┌─────────────────┐
│  User Workstation│ ◄──────────────► │   Axiom Server  │ ◄───────────────────► │  PostgreSQL DB  │
│  (Client Tier)   │                 │ (Application    │                       │   (Data Tier)   │
│                  │                 │     Tier)       │                       │                 │
└─────────────────┘                 └─────────────────┘                       └─────────────────┘
```

### 3-Tier Benefits
- **Security Isolation**: Prevents direct database access from workstations
- **Centralized Logic**: Business rules and security policies managed centrally  
- **Scalability**: Connection pooling and load distribution
- **Monitoring**: Centralized logging and audit trails
- **Access Control**: JWT-based authentication and role-based permissions

## Core Components

### 1. Authentication & Authorization System

#### JWT Token Management
- **Token Generation**: Issues JWT tokens upon successful authentication
- **Claims Structure**: Contains user ID, role ID, and permissions
- **Token Validation**: Middleware validates tokens on protected endpoints

```rust
pub struct Claims {
    pub sub: String,      // Username
    pub user_id: i32,     // Internal user ID
    pub role_id: i32,     // User's role for RBAC
    pub exp: usize,       // Token expiration
}
```

#### Role-Based Access Control (RBAC)
- **Permission Checking**: Validates user permissions before sensitive operations
- **Role Management**: Supports multiple roles with different privilege levels
- **Dynamic Authorization**: Real-time permission validation

### 2. Policy Management System

#### Application Policies
- **Sandboxing Rules**: Manages read/write permissions for applications
- **Network Controls**: TCP binding and connection restrictions
- **IP/Domain Filtering**: Controls network access by application and role

```rust
pub struct Policy {
    pub default_ro: String,        // Default read-only paths
    pub default_rw: String,        // Default read-write paths  
    pub tcp_bind: String,          // Allowed TCP bind ports
    pub tcp_connect: String,       // Allowed TCP connect ports
    pub allowed_ips: String,       // Permitted IP addresses
    pub allowed_domains: String,   // Permitted domains
}
```

#### Policy Change Workflow
- **Request System**: Users can request policy modifications
- **Approval Process**: Admin approval required for policy changes
- **Audit Trail**: All policy changes logged for compliance

### 3. Security Logging & Monitoring

#### Event Logging
- **Sandbox Events**: Logs from workstation sandboxers
- **Authentication Events**: Login attempts and failures
- **Policy Changes**: Administrative actions and approvals
- **Security Incidents**: Automated threat detection logging

#### Real-time Monitoring
- **Security Event Correlation**: Identifies suspicious patterns
- **Alert Generation**: Real-time notifications for security teams
- **Compliance Reporting**: Audit logs for regulatory requirements

### 4. Database Connection Management

#### Connection Pooling
- **r2d2 Pool**: Efficient PostgreSQL connection management
- **Connection Reuse**: Minimizes database overhead
- **Health Monitoring**: Automatic connection health checks

#### Transaction Management
- **ACID Compliance**: Ensures data consistency
- **Rollback Support**: Automatic rollback on errors
- **Concurrent Access**: Safe multi-user operations

## API Endpoints

### Authentication Endpoints
- `POST /auth/login` - User authentication and token generation
- `GET /whoami` - Current user information
- `GET /auth/roles` - User roles and permissions
- `GET /auth/ruleset` - User's sandbox policies

### Policy Management
- `GET /auth/ruleset` - Retrieve user's sandbox rules
- `POST /auth/ruleset/update` - Update application policies (admin)
- `POST /policy/request` - Request policy changes
- `GET /admin/policy/requests` - List pending policy requests (admin)
- `POST /admin/policy/requests/{id}` - Approve/reject policy requests (admin)

### Event Logging
- `POST /events/log` - Log sandbox events from workstations

## Security Features

### TLS/HTTPS Encryption
- **Self-Signed Certificates**: Development-ready TLS configuration
- **Certificate Management**: Automatic certificate generation and renewal
- **Secure Communication**: All data encrypted in transit

### Rate Limiting
- **DDoS Protection**: Prevents abuse and resource exhaustion
- **Per-IP Limits**: Configurable request rate limits
- **Burst Protection**: Handles traffic spikes gracefully

### Input Validation
- **Schema Validation**: All inputs validated against defined schemas
- **SQL Injection Prevention**: Parameterized queries only
- **XSS Protection**: Input sanitization and output encoding

### Error Handling
- **Secure Error Messages**: No sensitive information in error responses
- **Logging**: Detailed error logging for debugging
- **Graceful Degradation**: System remains operational during partial failures

## Configuration

### Environment Variables
```bash
# Database Configuration
DB_HOST=localhost
DB_PORT=5432
DB_NAME=supernanny
DB_USER=axiom_user
DB_PASS=secure_password

# JWT Configuration  
JWT_SECRET=your_jwt_secret_key

# Server Configuration
SERVER_PORT=8443
TLS_CERT_PATH=./certs/cert.pem
TLS_KEY_PATH=./certs/key.pem
```

### Dependencies
Key Rust dependencies powering the server:

- **axum**: Modern async web framework
- **tokio**: Async runtime for high performance
- **r2d2**: Database connection pooling
- **postgres**: PostgreSQL database driver
- **jsonwebtoken**: JWT token handling
- **bcrypt**: Password hashing
- **rustls**: TLS/SSL implementation
- **validator**: Input validation
- **tower_governor**: Rate limiting middleware

## Integration with SuperNanny Components

### 1. PAM Library Integration
- **Token Distribution**: Provides authentication tokens to workstations
- **Permission Sync**: Ensures workstation policies match server state
- **Session Management**: Tracks user sessions across the infrastructure

### 2. eBPF Interceptor Communication
- **Policy Delivery**: Sends sandboxing rules to eBPF modules
- **Event Reception**: Receives process execution events
- **Real-time Updates**: Pushes policy changes to active workstations

### 3. Sandboxer Coordination
- **Rule Enforcement**: Provides current policies for sandbox enforcement
- **Violation Reporting**: Receives and processes sandbox violations
- **Dynamic Policy Updates**: Updates sandboxer rules in real-time

## Deployment Architecture

### Production Deployment
```yaml
# Docker Compose Example
services:
  axiom-server:
    image: supernanny/axiom-server:latest
    ports:
      - "8443:8443"
    environment:
      - DB_HOST=postgres
      - JWT_SECRET=${JWT_SECRET}
    depends_on:
      - postgres
    volumes:
      - ./certs:/app/certs
    
  postgres:
    image: postgres:15
    environment:
      - POSTGRES_DB=supernanny
      - POSTGRES_USER=axiom_user
      - POSTGRES_PASSWORD=${DB_PASSWORD}
    volumes:
      - postgres_data:/var/lib/postgresql/data
```

### Kubernetes Deployment
- **High Availability**: Multiple server replicas
- **Load Balancing**: Service mesh integration
- **Secret Management**: Kubernetes secrets for sensitive data
- **Auto-scaling**: Based on CPU/memory usage

## Security Considerations

### Threat Mitigation
- **Man-in-the-Middle**: TLS encryption prevents traffic interception
- **Data Breach**: No direct database access from workstations
- **Privilege Escalation**: Strict RBAC prevents unauthorized access
- **Injection Attacks**: Parameterized queries and input validation

### Compliance Features
- **Audit Logging**: Complete audit trail of all operations
- **Data Retention**: Configurable log retention policies
- **Access Monitoring**: Real-time access pattern analysis
- **Compliance Reporting**: Automated compliance report generation

## Performance Optimization

### Connection Management
- **Pool Sizing**: Optimized for concurrent workstation connections
- **Connection Reuse**: Minimizes database connection overhead
- **Health Checks**: Proactive connection health monitoring

### Caching Strategy
- **Policy Caching**: Frequently accessed policies cached in memory
- **User Session Caching**: Reduces database queries for active users
- **Permission Caching**: Role permissions cached for performance

### Monitoring & Metrics
- **Prometheus Integration**: Detailed metrics collection
- **Health Endpoints**: Application health monitoring
- **Performance Tracking**: Response time and throughput monitoring

## Troubleshooting

### Common Issues
1. **Database Connection Failures**: Check connection string and database availability
2. **JWT Token Issues**: Verify JWT_SECRET configuration
3. **TLS Certificate Problems**: Ensure certificate files are readable
4. **Permission Denied Errors**: Check user roles and permissions in database

### Logging Configuration
```rust
// Enable detailed logging
RUST_LOG=debug cargo run

// Production logging
RUST_LOG=info,axiom_server=debug
```

## Future Enhancements

### Planned Features
- **Multi-tenancy**: Support for multiple organizations
- **Advanced Analytics**: ML-based threat detection
- **Policy Templates**: Pre-configured policy templates
- **API Rate Limiting**: More sophisticated rate limiting strategies
- **Certificate Automation**: Let's Encrypt integration

---

**SuperNanny Team**: CATALA Alexandre, CAILLEAUX Tanguy, MATILLA-NORO Lorenzo, VERNANCHET Louis  
**Institution**: ISEN Méditerranée  
**Project**: M1 Engineering Cybersecurity Solution
