//! SQLite persistence for runs, tasks, and findings via `sqlx`.
//!
//! The schema is created on connect (idempotent), so no external migration tool
//! is needed for this stage. Models are serialized to JSON columns where that is
//! simpler than normalizing (findings/services), while run/task status fields
//! are first-class columns so they can be queried and indexed.

use chrono::{DateTime, Utc};
use moosemap_core::model::{Finding, Run, RunStatus, Service, Task};
use sqlx::sqlite::{SqlitePoolOptions, SqliteConnectOptions};
use sqlx::{Pool, Sqlite};
use std::str::FromStr;
use uuid::Uuid;

#[derive(Clone)]
pub struct Store {
    pool: Pool<Sqlite>,
}

impl Store {
    /// Connect (creating the file if needed) and ensure the schema exists.
    /// `url` is a sqlite URL, e.g. `sqlite://moosemap.db` or `sqlite::memory:`.
    pub async fn connect(url: &str) -> anyhow::Result<Self> {
        let opts = SqliteConnectOptions::from_str(url)?.create_if_missing(true);
        let pool = SqlitePoolOptions::new()
            .max_connections(5)
            .connect_with(opts)
            .await?;
        let store = Store { pool };
        store.init_schema().await?;
        Ok(store)
    }

    async fn init_schema(&self) -> anyhow::Result<()> {
        sqlx::query(
            r#"
            CREATE TABLE IF NOT EXISTS runs (
                id          TEXT PRIMARY KEY,
                name        TEXT NOT NULL,
                scope       TEXT NOT NULL,     -- JSON array of strings
                status      TEXT NOT NULL,
                created_at  TEXT NOT NULL,
                updated_at  TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS tasks (
                id          TEXT PRIMARY KEY,
                run_id      TEXT NOT NULL REFERENCES runs(id) ON DELETE CASCADE,
                stage       TEXT NOT NULL,
                status      TEXT NOT NULL,
                message     TEXT,
                started_at  TEXT,
                finished_at TEXT
            );
            CREATE TABLE IF NOT EXISTS findings (
                id          TEXT PRIMARY KEY,
                run_id      TEXT NOT NULL REFERENCES runs(id) ON DELETE CASCADE,
                priority    REAL NOT NULL,
                severity    TEXT NOT NULL,
                data        TEXT NOT NULL      -- full Finding as JSON
            );
            CREATE TABLE IF NOT EXISTS services (
                run_id      TEXT NOT NULL REFERENCES runs(id) ON DELETE CASCADE,
                data        TEXT NOT NULL      -- full Service as JSON
            );
            CREATE INDEX IF NOT EXISTS idx_tasks_run ON tasks(run_id);
            CREATE INDEX IF NOT EXISTS idx_findings_run ON findings(run_id);
            CREATE INDEX IF NOT EXISTS idx_services_run ON services(run_id);
            "#,
        )
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    // ---- runs ----

    pub async fn insert_run(&self, run: &Run) -> anyhow::Result<()> {
        sqlx::query(
            "INSERT INTO runs (id, name, scope, status, created_at, updated_at)
             VALUES (?, ?, ?, ?, ?, ?)",
        )
        .bind(run.id.to_string())
        .bind(&run.name)
        .bind(serde_json::to_string(&run.scope)?)
        .bind(run.status.to_string())
        .bind(run.created_at.to_rfc3339())
        .bind(run.updated_at.to_rfc3339())
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    pub async fn update_run_status(
        &self,
        run_id: Uuid,
        status: RunStatus,
    ) -> anyhow::Result<()> {
        sqlx::query("UPDATE runs SET status = ?, updated_at = ? WHERE id = ?")
            .bind(status.to_string())
            .bind(Utc::now().to_rfc3339())
            .bind(run_id.to_string())
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    pub async fn list_runs(&self) -> anyhow::Result<Vec<Run>> {
        let rows: Vec<(String, String, String, String, String, String)> = sqlx::query_as(
            "SELECT id, name, scope, status, created_at, updated_at
             FROM runs ORDER BY created_at DESC",
        )
        .fetch_all(&self.pool)
        .await?;

        rows.into_iter()
            .map(|(id, name, scope, status, created, updated)| {
                Ok(Run {
                    id: Uuid::parse_str(&id)?,
                    name,
                    scope: serde_json::from_str(&scope)?,
                    status: parse_run_status(&status),
                    created_at: parse_dt(&created),
                    updated_at: parse_dt(&updated),
                })
            })
            .collect()
    }

    pub async fn get_run(&self, run_id: Uuid) -> anyhow::Result<Option<Run>> {
        let row: Option<(String, String, String, String, String, String)> = sqlx::query_as(
            "SELECT id, name, scope, status, created_at, updated_at
             FROM runs WHERE id = ?",
        )
        .bind(run_id.to_string())
        .fetch_optional(&self.pool)
        .await?;

        row.map(|(id, name, scope, status, created, updated)| {
            Ok(Run {
                id: Uuid::parse_str(&id)?,
                name,
                scope: serde_json::from_str(&scope)?,
                status: parse_run_status(&status),
                created_at: parse_dt(&created),
                updated_at: parse_dt(&updated),
            })
        })
        .transpose()
    }

    // ---- tasks ----

    /// Insert or update a task (upsert on primary key).
    pub async fn upsert_task(&self, task: &Task) -> anyhow::Result<()> {
        sqlx::query(
            "INSERT INTO tasks (id, run_id, stage, status, message, started_at, finished_at)
             VALUES (?, ?, ?, ?, ?, ?, ?)
             ON CONFLICT(id) DO UPDATE SET
                status = excluded.status,
                message = excluded.message,
                started_at = excluded.started_at,
                finished_at = excluded.finished_at",
        )
        .bind(task.id.to_string())
        .bind(task.run_id.to_string())
        .bind(task.stage.to_string())
        .bind(task.status.to_string())
        .bind(task.message.clone())
        .bind(task.started_at.map(|t| t.to_rfc3339()))
        .bind(task.finished_at.map(|t| t.to_rfc3339()))
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    pub async fn list_tasks(&self, run_id: Uuid) -> anyhow::Result<Vec<Task>> {
        let rows: Vec<(String, String, String, String, Option<String>, Option<String>, Option<String>)> =
            sqlx::query_as(
                "SELECT id, run_id, stage, status, message, started_at, finished_at
                 FROM tasks WHERE run_id = ?",
            )
            .bind(run_id.to_string())
            .fetch_all(&self.pool)
            .await?;

        rows.into_iter()
            .map(|(id, run_id, stage, status, message, started, finished)| {
                Ok(Task {
                    id: Uuid::parse_str(&id)?,
                    run_id: Uuid::parse_str(&run_id)?,
                    stage: parse_stage(&stage),
                    status: parse_task_status(&status),
                    message,
                    started_at: started.as_deref().map(parse_dt),
                    finished_at: finished.as_deref().map(parse_dt),
                })
            })
            .collect()
    }

    // ---- findings & services ----

    pub async fn insert_finding(&self, run_id: Uuid, f: &Finding) -> anyhow::Result<()> {
        sqlx::query(
            "INSERT INTO findings (id, run_id, priority, severity, data)
             VALUES (?, ?, ?, ?, ?)
             ON CONFLICT(id) DO UPDATE SET
                priority = excluded.priority,
                severity = excluded.severity,
                data = excluded.data",
        )
        .bind(f.id.to_string())
        .bind(run_id.to_string())
        .bind(f.priority as f64)
        .bind(f.severity.to_string())
        .bind(serde_json::to_string(f)?)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    pub async fn list_findings(&self, run_id: Uuid) -> anyhow::Result<Vec<Finding>> {
        let rows: Vec<(String,)> = sqlx::query_as(
            "SELECT data FROM findings WHERE run_id = ? ORDER BY priority DESC",
        )
        .bind(run_id.to_string())
        .fetch_all(&self.pool)
        .await?;
        rows.into_iter()
            .map(|(data,)| Ok(serde_json::from_str(&data)?))
            .collect()
    }

    pub async fn replace_services(
        &self,
        run_id: Uuid,
        services: &[Service],
    ) -> anyhow::Result<()> {
        let mut tx = self.pool.begin().await?;
        sqlx::query("DELETE FROM services WHERE run_id = ?")
            .bind(run_id.to_string())
            .execute(&mut *tx)
            .await?;
        for s in services {
            sqlx::query("INSERT INTO services (run_id, data) VALUES (?, ?)")
                .bind(run_id.to_string())
                .bind(serde_json::to_string(s)?)
                .execute(&mut *tx)
                .await?;
        }
        tx.commit().await?;
        Ok(())
    }

    pub async fn list_services(&self, run_id: Uuid) -> anyhow::Result<Vec<Service>> {
        let rows: Vec<(String,)> =
            sqlx::query_as("SELECT data FROM services WHERE run_id = ?")
                .bind(run_id.to_string())
                .fetch_all(&self.pool)
                .await?;
        rows.into_iter()
            .map(|(data,)| Ok(serde_json::from_str(&data)?))
            .collect()
    }
}

// ---- small parse helpers (tolerant; fall back to sensible defaults) ----

fn parse_dt(s: &str) -> DateTime<Utc> {
    DateTime::parse_from_rfc3339(s)
        .map(|d| d.with_timezone(&Utc))
        .unwrap_or_else(|_| Utc::now())
}

fn parse_run_status(s: &str) -> RunStatus {
    match s {
        "running" => RunStatus::Running,
        "completed" => RunStatus::Completed,
        "failed" => RunStatus::Failed,
        "cancelled" => RunStatus::Cancelled,
        _ => RunStatus::Pending,
    }
}

fn parse_task_status(s: &str) -> moosemap_core::model::TaskStatus {
    use moosemap_core::model::TaskStatus::*;
    match s {
        "running" => Running,
        "done" => Done,
        "failed" => Failed,
        "skipped" => Skipped,
        _ => Queued,
    }
}

fn parse_stage(s: &str) -> moosemap_core::model::Stage {
    use moosemap_core::model::Stage::*;
    match s {
        "port_scan" => PortScan,
        "service_enum" => ServiceEnum,
        "web_recon" => WebRecon,
        "vuln_scan" => VulnScan,
        "prioritize" => Prioritize,
        "report" => Report,
        _ => Discovery,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use moosemap_core::model::{Exploitability, Severity, Stage, Target, TaskStatus};

    async fn mem_store() -> Store {
        Store::connect("sqlite::memory:").await.unwrap()
    }

    #[tokio::test]
    async fn run_crud_roundtrip() {
        let store = mem_store().await;
        let run = Run::new("acme", vec!["192.0.2.0/24".into(), "example.com".into()]);
        store.insert_run(&run).await.unwrap();

        let fetched = store.get_run(run.id).await.unwrap().unwrap();
        assert_eq!(fetched.name, "acme");
        assert_eq!(fetched.scope.len(), 2);
        assert_eq!(fetched.status, RunStatus::Pending);

        store.update_run_status(run.id, RunStatus::Completed).await.unwrap();
        let fetched = store.get_run(run.id).await.unwrap().unwrap();
        assert_eq!(fetched.status, RunStatus::Completed);

        let all = store.list_runs().await.unwrap();
        assert_eq!(all.len(), 1);
    }

    #[tokio::test]
    async fn task_upsert_and_list() {
        let store = mem_store().await;
        let run = Run::new("r", vec![]);
        store.insert_run(&run).await.unwrap();

        let mut task = Task::new(run.id, Stage::PortScan);
        store.upsert_task(&task).await.unwrap();
        task.status = TaskStatus::Done;
        task.message = Some("found 3 ports".into());
        store.upsert_task(&task).await.unwrap();

        let tasks = store.list_tasks(run.id).await.unwrap();
        assert_eq!(tasks.len(), 1);
        assert_eq!(tasks[0].status, TaskStatus::Done);
        assert_eq!(tasks[0].stage, Stage::PortScan);
        assert_eq!(tasks[0].message.as_deref(), Some("found 3 ports"));
    }

    #[tokio::test]
    async fn findings_persist_and_sort_by_priority() {
        let store = mem_store().await;
        let run = Run::new("r", vec![]);
        store.insert_run(&run).await.unwrap();

        let mut low = Finding::new(
            Target::Ip("192.0.2.1".parse().unwrap()),
            Some(80),
            "low",
            "d",
            Severity::Low,
            Exploitability::None,
            "t",
        );
        low.priority = 1.0;
        let mut high = Finding::new(
            Target::Ip("192.0.2.1".parse().unwrap()),
            Some(443),
            "high",
            "d",
            Severity::Critical,
            Exploitability::Active,
            "t",
        );
        high.priority = 15.0;

        store.insert_finding(run.id, &low).await.unwrap();
        store.insert_finding(run.id, &high).await.unwrap();

        let got = store.list_findings(run.id).await.unwrap();
        assert_eq!(got.len(), 2);
        assert_eq!(got[0].title, "high"); // highest priority first
    }

    #[tokio::test]
    async fn services_replace() {
        let store = mem_store().await;
        let run = Run::new("r", vec![]);
        store.insert_run(&run).await.unwrap();

        use moosemap_core::model::{PortState, Protocol};
        let svc = Service {
            target: Target::Ip("192.0.2.1".parse().unwrap()),
            port: 22,
            protocol: Protocol::Tcp,
            state: PortState::Open,
            service_name: Some("ssh".into()),
            product: None,
            version: None,
        };
        store.replace_services(run.id, &[svc.clone()]).await.unwrap();
        store.replace_services(run.id, &[svc.clone(), svc.clone()]).await.unwrap();
        let got = store.list_services(run.id).await.unwrap();
        assert_eq!(got.len(), 2); // replaced, not appended to the first set
    }
}
