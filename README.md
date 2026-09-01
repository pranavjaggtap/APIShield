# APIShield

**An Intelligent Secure API Gateway for Threat Detection and Secure Microservice Communication**

---

## 1. Project Overview

APIShield is intended to become a reusable, intelligent security gateway for microservice-based applications. In its target form, APIShield will sit between clients and a set of backend microservices, inspecting, authenticating, and validating every incoming request before it is allowed to reach a downstream service — combining traditional API gateway routing with an active threat-detection and risk-scoring layer.

This repository currently contains the **foundation** of that system: a working reactive API gateway built on Spring Cloud Gateway, plus a minimal downstream microservice used to demonstrate and verify routing behavior end to end.

---

## 2. Current Implementation — Phase 1

**Phase 1 implements only the gateway foundation and request routing.** No authentication, security, or threat-detection logic has been implemented yet.

Technology stack used in Phase 1:

- **Java 21**
- **Spring Boot 4.1.1**
- **Spring WebFlux** — reactive, non-blocking web stack (replaces the default Spring MVC/servlet stack)
- **Spring Cloud Gateway Server WebFlux** (`spring-cloud-starter-gateway-server-webflux`, via the Spring Cloud `2025.1.2` release train) — the routing/gateway engine
- **Reactor Netty** — the embedded reactive HTTP server
- **Maven** — build and dependency management

---

## 3. Current Architecture

```
                Client
                  |
                  v
        APIShield Gateway :8080
                  |
                  v
        Spring Cloud Gateway
        (route matching + path rewrite)
                  |
                  v
          User Service :8081
```

---

## 4. Request Flow

A request for `GET /api/users/1` flows through the system as follows:

1. Client sends `GET /api/users/1` to **APIShield** on port `8080`.
2. Spring Cloud Gateway evaluates its configured routes and matches the request against the `Path=/api/users/**` predicate.
3. The `RewritePath` filter rewrites the path from `/api/users/1` to `/users/1`.
4. The rewritten request is forwarded to the **User Service** on port `8081`.
5. The User Service returns a JSON response, which is passed back through APIShield to the original client unchanged.

---

## 5. Current Services

### APIShield Gateway
The main project in this repository. A Spring Boot 4.1.1 application built on Spring WebFlux and Spring Cloud Gateway Server WebFlux. It currently has one responsibility: match incoming requests against configured routes and forward them to the correct downstream service. It runs on port `8080`.

### User Service
A separate, minimal Spring Boot application used purely as a **downstream demonstration service** to prove that gateway routing works correctly. It is not part of APIShield's core codebase — it represents "some microservice" that a real deployment would route traffic to. It exposes a single endpoint, `GET /users/{id}`, and runs on port `8081`.

---

## 6. Project Structure

```
APIShield/                                  # Gateway project (this repository)
├── pom.xml                                 # Maven config: Spring Boot 4.1.1, WebFlux, Gateway, Spring Cloud BOM
├── mvnw, mvnw.cmd                          # Maven wrapper
├── HELP.md                                 # Spring Initializr default reference doc
└── src/
    ├── main/
    │   ├── java/com/apishield/
    │   │   └── ApiShieldApplication.java   # Spring Boot entry point
    │   └── resources/
    │       └── application.yml             # Gateway route configuration, server.port=8080
    └── test/
        └── java/com/apishield/
            └── ApiShieldApplicationTests.java  # Application context load test

user-service/                               # Sibling project — downstream demo service
├── pom.xml                                 # Maven config: Spring Boot 4.1.1, Spring MVC
└── src/
    ├── main/
    │   ├── java/com/apishield/userservice/
    │   │   ├── UserServiceApplication.java # Spring Boot entry point
    │   │   └── UserController.java         # GET /users/{id} endpoint
    │   └── resources/
    │       └── application.yml             # server.port=8081
    └── test/
        └── java/com/apishield/userservice/
            └── UserControllerTest.java     # MockMvc test for /users/{id}
```

`user-service` lives alongside `APIShield` (both under `~/Desktop/APIShield/`) as an independent Maven project — it is not a Maven module of APIShield, reflecting the fact that in the target architecture, gateway and backend microservices are separate deployables.

---

## 7. Running the Project

Two services must be started in separate terminals.

**Terminal 1 — start the User Service (port 8081):**
```bash
cd ~/Desktop/APIShield/user-service
../APIShield/mvnw spring-boot:run
```

**Terminal 2 — start APIShield (port 8080):**
```bash
cd ~/Desktop/APIShield/APIShield
./mvnw spring-boot:run
```

---

## 8. Testing

With both services running, verify the routing with:

```bash
curl -i http://localhost:8080/api/users/1
```

A successful `HTTP/1.1 200 OK` response containing the User Service's JSON body proves that:
- APIShield received the request on port `8080`,
- matched it against the configured gateway route,
- rewrote and forwarded it to the User Service on port `8081`,
- and returned the downstream response back to the client.

---

## 9. Demonstrated Result

```
Client → APIShield :8080 → User Service :8081
```

Example response:

```json
{
  "id": 1,
  "name": "John Doe",
  "email": "john@example.com",
  "source": "user-service"
}
```

The `"source": "user-service"` field is included specifically to prove that the JSON response returned to the client originated from the downstream User Service, not from APIShield itself — confirming that the gateway is genuinely proxying the request rather than serving a local/mocked response.

---

## 10. Research Motivation

Phase 1 establishes the structural foundation for the project's intended research contribution: an **intelligent security layer** embedded directly in the API gateway path, capable of analyzing, scoring, and making allow/block decisions on incoming requests *before* they are forwarded to backend microservices — rather than relying solely on perimeter firewalls or downstream service-level checks. Having a working, reactive routing layer in place is a prerequisite for building and evaluating that security layer in later phases.

---

## 11. Planned Security Modules (FUTURE / UPCOMING — not yet implemented)

The following capabilities are planned for later phases and are **not present in the current codebase**:

- JWT authentication
- API key validation
- Request validation
- Redis-based rate limiting
- Replay attack detection
- SQL injection detection
- XSS detection
- Bot/abuse detection
- Request frequency analysis
- Dynamic risk scoring
- Decision engine (ALLOW / BLOCK)
- PostgreSQL-backed security event storage
- React security dashboard
- ML-based anomaly detection

---

## 12. Planned Final Architecture

```
                         Client
                           |
                           v
                       APIShield
                           |
                           v
                     Authentication
                           |
                           v
                  API Key Validation
                           |
                           v
                   Request Validation
                           |
                           v
                     Rate Limiting  <---------------  Redis
                           |
                           v
                Threat Detection Engine
                           |
                           v
                  Risk Score Engine
                           |
                           v
                   Decision Engine
                     (ALLOW / BLOCK)
                           |
                           v
              Spring Cloud Gateway Routing
                           |
             ------------------------------
             |             |              |
             v             v              v
       Microservice A  Microservice B  Microservice N

  Security events from every stage are persisted to PostgreSQL,
  surfaced on a React security Dashboard, and later analyzed by
  a future ML-based anomaly detection component.
```

---

## 13. Development Roadmap

- **Phase 1 — Gateway Foundation — COMPLETED**
- **Phase 2 — Redis + PostgreSQL Infrastructure**
- **Phase 3 — Authentication & Authorization**
- **Phase 4 — Threat Detection Engine**
- **Phase 5 — Risk Scoring & Decision Engine**
- **Phase 6 — Security Logging & Analytics**
- **Phase 7 — React Dashboard**
- **Phase 8 — ML-based Anomaly Detection**
- **Phase 9 — Dockerized Deployment & Reusable Distribution**

---

## 14. Future Goal

The long-term goal for APIShield is to become a **reusable, drop-in security gateway** that can be placed in front of any set of microservices through configuration alone — not one hard-wired to the demonstration User Service used in Phase 1. As later phases add authentication, threat detection, risk scoring, and logging, these capabilities are intended to be generic and configurable, so that APIShield can be deployed in front of different backend systems without changing its core code.
