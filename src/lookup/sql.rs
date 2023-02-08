use super::{SqlDatabase, SqlQuery};

impl SqlQuery {
    pub async fn exists(&self, param: &str) -> Option<bool> {
        if let Some(result) = self
            .cache
            .as_ref()
            .and_then(|cache| cache.lock().get(param))
        {
            return Some(result);
        }
        let result = match &self.db {
            super::SqlDatabase::Postgres(pool) => {
                sqlx::query_scalar::<_, bool>(&self.query)
                    .bind(param)
                    .fetch_one(pool)
                    .await
            }
            super::SqlDatabase::MySql(pool) => {
                sqlx::query_scalar::<_, bool>(&self.query)
                    .bind(param)
                    .fetch_one(pool)
                    .await
            }
            super::SqlDatabase::MsSql(pool) => {
                sqlx::query_scalar::<_, bool>(&self.query)
                    .bind(param)
                    .fetch_one(pool)
                    .await
            }
            super::SqlDatabase::SqlLite(pool) => {
                sqlx::query_scalar::<_, bool>(&self.query)
                    .bind(param)
                    .fetch_one(pool)
                    .await
            }
        };

        match result {
            Ok(result) => {
                if let Some(cache) = &self.cache {
                    if result {
                        cache.lock().insert_pos(param.to_string());
                    } else {
                        cache.lock().insert_neg(param.to_string());
                    }
                }
                Some(result)
            }
            Err(err) => {
                tracing::warn!(context = "sql", event = "error", query = self.query, reason = ?err);
                None
            }
        }
    }

    pub async fn fetch_one(&self, param: &str) -> Option<Option<String>> {
        let result = match &self.db {
            super::SqlDatabase::Postgres(pool) => {
                sqlx::query_scalar::<_, String>(&self.query)
                    .bind(param)
                    .fetch_optional(pool)
                    .await
            }
            super::SqlDatabase::MySql(pool) => {
                sqlx::query_scalar::<_, String>(&self.query)
                    .bind(param)
                    .fetch_optional(pool)
                    .await
            }
            super::SqlDatabase::MsSql(pool) => {
                sqlx::query_scalar::<_, String>(&self.query)
                    .bind(param)
                    .fetch_optional(pool)
                    .await
            }
            super::SqlDatabase::SqlLite(pool) => {
                sqlx::query_scalar::<_, String>(&self.query)
                    .bind(param)
                    .fetch_optional(pool)
                    .await
            }
        };

        match result {
            Ok(result) => Some(result),
            Err(err) => {
                tracing::warn!(context = "sql", event = "error", query = self.query, reason = ?err);
                None
            }
        }
    }

    pub async fn fetch_many(&self, param: &str) -> Option<Vec<String>> {
        let result = match &self.db {
            super::SqlDatabase::Postgres(pool) => {
                sqlx::query_scalar::<_, String>(&self.query)
                    .bind(param)
                    .fetch_all(pool)
                    .await
            }
            super::SqlDatabase::MySql(pool) => {
                sqlx::query_scalar::<_, String>(&self.query)
                    .bind(param)
                    .fetch_all(pool)
                    .await
            }
            super::SqlDatabase::MsSql(pool) => {
                sqlx::query_scalar::<_, String>(&self.query)
                    .bind(param)
                    .fetch_all(pool)
                    .await
            }
            super::SqlDatabase::SqlLite(pool) => {
                sqlx::query_scalar::<_, String>(&self.query)
                    .bind(param)
                    .fetch_all(pool)
                    .await
            }
        };

        match result {
            Ok(result) => Some(result),
            Err(err) => {
                tracing::warn!(context = "sql", event = "error", query = self.query, reason = ?err);
                None
            }
        }
    }
}

impl SqlDatabase {
    pub async fn exists(&self, query: &str, params: impl Iterator<Item = String>) -> Option<bool> {
        let result = match self {
            super::SqlDatabase::Postgres(pool) => {
                let mut q = sqlx::query_scalar::<_, bool>(query);
                for param in params {
                    q = q.bind(param);
                }
                q.fetch_one(pool).await
            }
            super::SqlDatabase::MySql(pool) => {
                let mut q = sqlx::query_scalar::<_, bool>(query);
                for param in params {
                    q = q.bind(param);
                }
                q.fetch_one(pool).await
            }
            super::SqlDatabase::MsSql(pool) => {
                let mut q = sqlx::query_scalar::<_, bool>(query);
                for param in params {
                    q = q.bind(param);
                }
                q.fetch_one(pool).await
            }
            super::SqlDatabase::SqlLite(pool) => {
                let mut q = sqlx::query_scalar::<_, bool>(query);
                for param in params {
                    q = q.bind(param);
                }
                q.fetch_one(pool).await
            }
        };

        match result {
            Ok(result) => Some(result),
            Err(err) => {
                tracing::warn!(context = "sql", event = "error", query = query, reason = ?err);
                None
            }
        }
    }

    pub async fn execute(&self, query: &str, params: impl Iterator<Item = String>) -> bool {
        let result = match self {
            super::SqlDatabase::Postgres(pool) => {
                let mut q = sqlx::query(query);
                for param in params {
                    q = q.bind(param);
                }
                q.execute(pool).await.map(|_| ())
            }
            super::SqlDatabase::MySql(pool) => {
                let mut q = sqlx::query(query);
                for param in params {
                    q = q.bind(param);
                }
                q.execute(pool).await.map(|_| ())
            }
            super::SqlDatabase::MsSql(pool) => {
                let mut q = sqlx::query(query);
                for param in params {
                    q = q.bind(param);
                }
                q.execute(pool).await.map(|_| ())
            }
            super::SqlDatabase::SqlLite(pool) => {
                let mut q = sqlx::query(query);
                for param in params {
                    q = q.bind(param);
                }
                q.execute(pool).await.map(|_| ())
            }
        };

        match result {
            Ok(_) => true,
            Err(err) => {
                tracing::warn!(context = "sql", event = "error", query = query, reason = ?err);
                false
            }
        }
    }
}
