# devPulse

> **AI-driven engineering analytics for high-performing teams.** devPulse is a multi-tenant full-stack developer velocity platform. It securely orchestrates GitHub OAuth authentication, processes repository and organization PR workflows via asynchronous pipelines, and delivers AI-powered bottleneck analysis through an interactive dashboard.

## 🚀 Tech Stack & Architecture

The project is built with a highly decoupled, modern architectural pattern:

* **Frontend:** **Next.js** (React) – Utilized as a Backend-for-Frontend (BFF) layer for secure GitHub token exchange, server-side rendering for public pages, and dynamic client components for analytics dashboards.
* **Backend:** **FastAPI** (Python) – A high-performance, asynchronous API gateway managing multi-tenant business logic, data processing, and AI integrations.
* **Database & ORM:** **PostgreSQL** paired with **SQLAlchemy** (Async ORM) for powerful, type-safe data modeling.
* **Migrations:** **Alembic** handling seamless database schema version control.
* **DevOps & Deployment:** **Docker** for containerized local development and **GitHub Actions** automating the CI/CD pipeline.