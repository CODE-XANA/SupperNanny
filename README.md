# SuperNanny

<img src="https://i.ibb.co/bgV6DpX4/image-2025-05-31-152756196.png" alt="Supernanny Logo" width="200" height="200">


> **Advanced Sandboxing System for Linux Workstations**

A cybersecurity project developed by the ISEN Méditerranée team as part of the Master Project M1 Cybersecurity.

![ISEN Logo](https://upload.wikimedia.org/wikipedia/fr/f/f0/Yncrea_BM_ISEN-_horizontal-1.jpg)

## Development Team

- **CATALA Alexandre**
- **CAILLEAUX Tanguy** 
- **MATILLA-NORO Lorenzo**
- **VERNANCHET Louis**

## Project Overview

SuperNanny is an innovative security solution designed to protect Linux workstations by automatically sandboxing all applications launched by users. The system implements a secure three-tier architecture with centralized authentication, Role-Based Access Control (RBAC), and real-time monitoring.

### Key Objectives

- **Proactive Security**: Automatic sandboxing of all user applications
- **Granular Control**: Fine-grained permission management by role and application
- **Advanced Monitoring**: Real-time surveillance with automated alerting
- **Secure Architecture**: Clear separation between data access layers

## System Architecture

```mermaid
graph TB
    %% User Workstation Flow
    User[User Workstation] --> PAM[PAM SuperNanny Library]
    PAM --> Auth[Axiom Authentication Server]
    Auth --> Token[JWT Token + Permissions]
    
    User --> App[User Application]
    App --> eBPF[eBPF Interceptor]
    eBPF --> Kill[Kill Original Process]
    eBPF --> Relaunch[Relaunch via Sandboxer]
    
    %% Sandboxing Flow
    Relaunch --> Sandbox[SuperNanny Sandboxer]
    Sandbox --> Landlock[Landlock LSM]
    Sandbox --> Policy[Apply Security Policy]
    Token --> Policy
    
    Policy --> Exec[Execute Sandboxed App]
    Exec --> Monitor[Monitor & Log Events]
    Monitor --> DB[(PostgreSQL Database)]
    
    %% Admin Interface Flow
    Admin[Admin Interface] --> API[Rust API]
    API --> RateLimit[Rate Limit Middleware]
    RateLimit --> TokenVerif[Token Verification]
    TokenVerif --> ReqLogger[Request Logger]
    ReqLogger --> AdminServices[Admin Services]
    
    AdminServices --> Auth
    AdminServices --> DB
    
    %% Monitoring & Alerting
    DB --> Grafana[Grafana Dashboards]
    DB --> Alerting[Real-time Alerting System]
    DB --> TrafficAnalysis[Traffic Analysis & Security Logs]
    TrafficAnalysis --> SecurityAnom[Security Anomaly Detection]
    
    %% Styling
    style Sandbox fill:#ff9999
    style Landlock fill:#99ff99
    style Policy fill:#9999ff
    style Auth fill:#e8f5e8
    style DB fill:#f3e5f5
    style Admin fill:#fff3e0
    style Grafana fill:#ffebee
```

## Technical Components

### User Workstation Side

#### 1. **PAM SuperNanny Library**
The PAM (Pluggable Authentication Modules) SuperNanny library seamlessly integrates into the standard Linux authentication flow. When users authenticate on their Linux system, they simultaneously authenticate with the SuperNanny server to retrieve their JWT token with associated permissions. These tokens are subsequently used by the sandboxer to apply security rules on processes executed by the user.

**Key Features:**
- Transparent integration with existing Linux authentication
- Secure credential management
- Automatic token retrieval and caching
- Seamless user experience

#### 2. **eBPF Interceptor**
The eBPF interceptor module captures all `execve` and `execveat` system calls in real-time. Upon detection, it immediately terminates the launched process and relaunches it in "sandboxed" mode using the sandboxer binary. This approach ensures that no application can execute outside the controlled environment.

**Technical Implementation:**
- Kernel-level interception using eBPF programs
- Zero-latency process termination
- Automatic relaunch mechanism
- Minimal system performance impact

#### 3. **Landlock Sandboxer**
The sandboxer, built using the Landlock LSM (Linux Security Module), ensures that applications run within a strictly defined sandboxed environment. Each process is confined and executes with specifically defined and granted rights. Any security violations are automatically logged to the database.

**Security Features:**
- Complete process isolation
- Granular permission enforcement
- File system access control
- Network access restrictions
- Comprehensive violation logging

### Axiom Server (3-Tier Architecture)

The Axiom server, developed in Rust, serves as the secure intermediary layer between workstations and the database, implementing a robust 3-tier architecture:

**Core Responsibilities:**
- User connection management with robust authentication
- JWT token creation and validation with automatic expiration
- Secure proxy for all database access
- RESTful API for administrative interfaces
- Request validation and sanitization
- Centralized policy enforcement

**Security Benefits:**
- Prevents direct database access from workstations
- Centralized security policy management
- Comprehensive audit logging
- Protection against SQL injection and other attacks

### PostgreSQL Database

The central database securely stores all system information:

**Data Categories:**
- **User Management**: User accounts, credentials with secure hashing
- **Role-Based Access Control**: Roles, permissions, and access matrices
- **Security Policies**: Default rules and custom application-specific rules
- **Audit Logs**: Comprehensive logging with timestamps and user attribution
- **Performance Metrics**: System usage statistics and performance data

### Administrative Interface

#### **Rust API**
The administrative API provides secure endpoints for system management:
- User, role, and permission management
- Security rule configuration (default and per-application)
- Real-time log access and filtering
- System metrics and performance monitoring
- Automated report generation

#### **Monitoring & Alerting**
- **Grafana Dashboards**: Real-time visualization of security metrics
- **Real-time Alerting**: Traffic-based anomaly detection and notification
- **Behavioral Analysis**: Pattern recognition for threat detection
- **Automated Reporting**: Scheduled security and compliance reports

## CI/CD Pipeline

### Continuous Integration (GitHub Actions)
```yaml
Triggers: Push to main branches
Automated Actions:
  - Unit and integration testing
  - Static code analysis for Rust codebase
  - Docker container builds
  - Security scanning of container images
  - Push to secure container registry
```

### Continuous Deployment (Ansible)
```yaml
Environments: Development → Staging → Production
Automation Features:
  - Orchestrated Kubernetes deployment
  - Secure secrets management
  - Automated health checks
  - Automatic rollback on failure
```

## Sequence Diagrams

### User Authentication Flow

```mermaid
sequenceDiagram
    participant U as User
    participant PAM as PAM SuperNanny Module
    participant WS as Linux Workstation
    participant AX as Axiom Server (Rust)
    participant DB as PostgreSQL

    Note over U,DB: System and SuperNanny authentication phase

    U->>WS: Login to Linux system
    WS->>PAM: Trigger authentication
    PAM->>U: Request SuperNanny credentials
    U->>PAM: SuperNanny Username/Password

    Note over PAM,AX: Secure TLS communication
    PAM->>AX: Authentication request + credentials
    AX->>DB: Validate user and role
    DB-->>AX: Validated user data

    Note over AX: Generate JWT with role-based permissions
    AX->>AX: Create JWT token (secret + expiry)
    AX-->>PAM: JWT token + user permissions

    PAM->>WS: Store token in secure memory
    PAM-->>U: Authentication successful

    Note over U,DB: User connected with active token

```

### Sandboxed Application Execution

```mermaid
sequenceDiagram
    participant User as User
    participant App as Application
    participant eBPF as eBPF Interceptor
    participant Sandbox as Sandboxer (LandLock)
    participant Axiom as Axiom Server
    participant DB as PostgreSQL

    Note over User, DB: User launches an application
    User->>App: Launch application (execve)
    App->>eBPF: Intercept execve/execveat
    eBPF-->>App: Kill original process

    Note over Sandbox, DB: Sandboxer retrieves token and permissions
    Sandbox->>Sandbox: Load stored JWT token (set earlier by PAM)
    Sandbox->>Axiom: Validate token + retrieve rules
    Axiom->>DB: Query user/app permissions
    DB-->>Axiom: Specific sandboxing rules
    Axiom-->>Sandbox: Validated sandbox configuration

    Note over Sandbox: Apply LandLock restrictions
    Sandbox->>Sandbox: Setup LSM environment
    Sandbox->>Sandbox: Apply filesystem/network restrictions
    Sandbox->>App: Relaunch application in sandbox
    App->>App: Executes in restricted environment

    alt Security violation
        App->>Sandbox: Attempt unauthorized access
        Sandbox->>DB: Log security event
        Sandbox-->>App: Block operation
    else Normal operation
        App-->>User: Application runs as expected
    end
```

### Administrative Management

```mermaid
sequenceDiagram
    participant Admin as Administrator
    participant Web as Web Frontend
    participant API as Admin API (Rust)
    participant DB as PostgreSQL
    participant Monitor as Monitoring (Grafana)
    participant Alert as Alert System

    Note over Admin, Alert: System administration
    Admin->>Web: Login to admin interface
    Web->>API: Admin authentication
    API->>DB: Verify admin rights
    DB-->>API: Admin permission granted
    API-->>Web: Admin session established

    Note over Admin, Alert: Manage users and policies
    Admin->>Web: Create new user
    Web->>API: User creation request
    API->>API: Check admin rights (CRUD users)
    API->>DB: Insert new user
    DB-->>API: User created
    API-->>Web: Success confirmation

    Admin->>Web: Configure application policies
    Web->>API: New security policy
    API->>API: Validate rights (manage_policies)
    API->>DB: Update sandboxing rules
    DB-->>API: Policy saved

    Note over Monitor, Alert: Real-time monitoring
    Monitor->>Monitor: Continuous log stream
    Monitor->>Monitor: Analyze security patterns
    Note over Monitor: [Anomaly detected]
    Monitor->>Alert: Trigger alert
    Alert->>Admin: Real-time notification

    Admin->>Web: Incident investigation
    Web->>API: Request log details
    API->>DB: Extract detailed logs
    DB-->>API: Forensics data
    API-->>Web: Full incident report
```

## Technology Stack

- **Primary Language**: Rust
- **Database**: PostgreSQL
- **Containerization**: Docker
- **Orchestration**: Kubernetes
- **CI/CD**: GitHub Actions + Ansible
- **Monitoring**: Grafana
- **Security**: eBPF + Landlock LSM

## Key Features

### Security
- Automatic and transparent sandboxing
- Robust centralized authentication
- Role-Based Access Control (RBAC)
- End-to-end encryption of communications
- Comprehensive action auditing

### Administration
- Intuitive web interface
- Granular permission management
- Rule configuration by role and application
- Real-time monitoring capabilities
- Advanced alerting system

### Performance
- Minimal system performance impact
- Optimized eBPF interception
- Scalable distributed architecture
- Intelligent rule caching

## Installation and Deployment

### Prerequisites
```bash
# Linux system with eBPF and Landlock support
kernel >= 5.13
# Docker and Kubernetes
# PostgreSQL 13+
# Rust toolchain
```

### Quick Deployment
```bash
git clone https://github.com/team/SupperNanny
cd SupperNanny
sudo apt install ansible
ansible-playbook main.yml --ask-become-pass
```

## Metrics and Monitoring

The system provides detailed metrics on:
- **Performance**: Execution latency, throughput measurements
- **Security**: Detected violations, escalation attempts
- **Usage**: Most used applications, usage patterns
- **System Health**: Resource consumption, error rates

## Technical Innovation

SuperNanny represents a significant advancement in workstation security through:

1. **Seamless Integration**: Zero-configuration security enhancement for existing Linux systems
2. **Performance Optimization**: Kernel-level interception with minimal overhead
3. **Comprehensive Coverage**: Every process execution is automatically secured
4. **Centralized Management**: Enterprise-scale administration and monitoring
5. **Real-time Response**: Immediate threat detection and mitigation

## Academic Context

This project was developed as part of the Master 1 Engineering program at ISEN Méditerranée, demonstrating advanced concepts in:
- Systems programming with Rust
- Linux kernel security mechanisms
- Distributed system architecture
- DevOps and automation practices
- Cybersecurity implementation

## License

Academic Project - ISEN Méditerranée 2024-2025

---

**SuperNanny** - *Proactive Security for Linux Workstations*
