# SecureCode Analyzer

SecureCode Analyzer is a Java 17 Spring Boot backend application that scans Java GitHub repositories and generates structured static-analysis reports.

The project focuses on backend engineering concepts such as REST APIs, layered architecture, repository processing, static code analysis, AST parsing, exception handling, and JSON report generation.

It is designed as an interview-friendly backend project inspired by tools like SonarQube and DevSecOps scanners.

---

# Features

- Clone and analyze public GitHub repositories
- Parse Java source code using JavaParser
- Detect common security vulnerabilities and coding issues
- Scan Maven and Gradle dependencies for vulnerable libraries
- Generate structured JSON analysis reports
- REST API-based architecture using Spring Boot
- Modular analyzer architecture for easy rule extension

---

# Tech Stack

- Java 17
- Spring Boot 3
- Maven
- JavaParser
- JGit
- Lombok
- Jackson
- JUnit

---

# Project Architecture

```text
Client
   ↓
CodeReviewController
   ↓
CodeReviewService
   ↓
GitHubService
   ↓
Analyzers / VulnerabilityScanner
   ↓
CodeReviewResult JSON
```

---

# Project Structure

```text
src/main/java/com/codereview

controller/
  CodeReviewController
  GlobalExceptionHandler

service/
  CodeReviewService
  GitHubService
  VulnerabilityScanner

analyzer/
  AbstractJavaAnalyzer
  CodeAnalyzer

analyzer/sonar/
  SecurityAnalyzer
  BugAnalyzer
  CodeSmellAnalyzer

model/
  ReviewRequest
  CodeReviewResult
  CodeIssue
  VulnerableDependency

config/
  CodeReviewProperties
```

---

# Analyzer Modules

## Security Analyzer
Detects:
- SQL injection patterns
- Command injection risks
- Hardcoded credentials
- Weak cryptography usage
- Insecure random usage
- Path traversal vulnerabilities

## Bug Analyzer
Detects:
- Null pointer risks
- String comparison using `==`
- Return inside `finally`
- Infinite loops
- hashCode/equals mismatch

## Code Smell Analyzer
Detects:
- Long methods
- Magic numbers
- Empty catch blocks
- TODO/FIXME comments
- Excessive method parameters

---

# API Endpoints

## Check Service Status

```http
GET /api/v1/review/status
```

### Sample Response

```json
{
  "enabled": true,
  "message": "Code Review Service is enabled"
}
```

---

## Analyze Repository

```http
POST /api/v1/review
Content-Type: application/json
```

### Request Body

```json
{
  "repositoryUrl": "https://github.com/owner/repository",
  "branch": "main",
  "commitSha": "",
  "options": {
    "sonarQubeRulesEnabled": true,
    "vulnerabilityScanEnabled": true
  }
}
```

---

# Sample Analysis Response

```json
{
  "status": "SUCCESS",
  "summary": {
    "totalIssues": 12,
    "qualityGateStatus": "FAILED"
  }
}
```

---

# Run Locally

## Start Application

```bash
mvn spring-boot:run
```

Application runs on:

```text
http://localhost:8080
```

---

# Run Tests

```bash
mvn test
```

---

# Current Status

- Backend APIs fully functional
- Repository scanning operational
- Java static analysis implemented
- JSON reporting implemented
- Tested using Postman
- Built and tested with Maven + Java 17

---

# Future Improvements

- Frontend dashboard
- Multi-language support
- Docker deployment
- CI/CD integration
- Authentication & authorization
- Cloud deployment support

---

# Learning Outcomes

This project helped in understanding:
- Spring Boot backend development
- REST API design
- Static code analysis concepts
- AST parsing using JavaParser
- Git repository processing
- Clean layered architecture
- Exception handling and validation