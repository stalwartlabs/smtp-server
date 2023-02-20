use std::{sync::Arc, time::Duration};

use parking_lot::Mutex;
use sqlx::{
    mssql::MssqlPoolOptions, mysql::MySqlPoolOptions, postgres::PgPoolOptions,
    sqlite::SqlitePoolOptions,
};

use crate::lookup::{cache::LookupCache, Lookup, SqlDatabase, SqlQuery};

use super::{utils::AsKey, Config, ConfigContext};

impl Config {
    pub fn parse_databases(&self, ctx: &mut ConfigContext) -> super::Result<()> {
        for id in self.sub_keys("database") {
            self.parse_database(id, ctx)?;
        }

        Ok(())
    }

    fn parse_database(&self, id: &str, ctx: &mut ConfigContext) -> super::Result<()> {
        let address = self.value_require(("database", id, "address"))?;
        let pool = if address.starts_with("postgres:") {
            SqlDatabase::Postgres(
                PgPoolOptions::new()
                    .max_connections(
                        self.property(("database", id, "max-connections"))?
                            .unwrap_or(10),
                    )
                    .min_connections(
                        self.property(("database", id, "min-connections"))?
                            .unwrap_or(0),
                    )
                    .idle_timeout(self.property(("database", id, "idle-timeout"))?)
                    .connect_lazy(address)
                    .map_err(|err| {
                        format!("Failed to create connection pool for {address:?}: {err}")
                    })?,
            )
        } else if address.starts_with("mysql:") {
            SqlDatabase::MySql(
                MySqlPoolOptions::new()
                    .max_connections(
                        self.property(("database", id, "max-connections"))?
                            .unwrap_or(10),
                    )
                    .min_connections(
                        self.property(("database", id, "min-connections"))?
                            .unwrap_or(0),
                    )
                    .idle_timeout(self.property(("database", id, "idle-timeout"))?)
                    .connect_lazy(address)
                    .map_err(|err| {
                        format!("Failed to create connection pool for {address:?}: {err}")
                    })?,
            )
        } else if address.starts_with("mssql:") {
            SqlDatabase::MsSql(
                MssqlPoolOptions::new()
                    .max_connections(
                        self.property(("database", id, "max-connections"))?
                            .unwrap_or(10),
                    )
                    .min_connections(
                        self.property(("database", id, "min-connections"))?
                            .unwrap_or(0),
                    )
                    .idle_timeout(self.property(("database", id, "idle-timeout"))?)
                    .connect_lazy(address)
                    .map_err(|err| {
                        format!("Failed to create connection pool for {address:?}: {err}")
                    })?,
            )
        } else if address.starts_with("sqlite:") {
            SqlDatabase::SqlLite(
                SqlitePoolOptions::new()
                    .max_connections(
                        self.property(("database", id, "max-connections"))?
                            .unwrap_or(10),
                    )
                    .min_connections(
                        self.property(("database", id, "min-connections"))?
                            .unwrap_or(0),
                    )
                    .idle_timeout(self.property(("database", id, "idle-timeout"))?)
                    .connect_lazy(address)
                    .map_err(|err| {
                        format!("Failed to create connection pool for {address:?}: {err}")
                    })?,
            )
        } else {
            return Err(format!(
                "Invalid database address {:?} for key {:?}",
                address,
                ("database", id, "address").as_key()
            ));
        };

        // Add database
        ctx.databases.insert(id.to_string(), pool.clone());

        // Parse cache
        let cache_entries = self
            .property(("database", id, "cache.entries"))?
            .unwrap_or(1024);
        let cache_ttl_positive = self
            .property(("database", id, "cache.ttl.positive"))?
            .unwrap_or(Duration::from_secs(86400));
        let cache_ttl_negative = self
            .property(("database", id, "cache.ttl.positive"))?
            .unwrap_or(Duration::from_secs(3600));
        let cache_enable = self
            .values(("database", id, "cache.enable"))
            .map(|(_, v)| v)
            .collect::<Vec<_>>();

        // Parse lookups
        for lookup_id in self.sub_keys(("database", id, "lookup")) {
            ctx.lookup.insert(
                format!("db/{id}/{lookup_id}"),
                Arc::new(Lookup::Sql(SqlQuery {
                    query: self
                        .value_require(("database", id, "lookup", lookup_id))?
                        .to_string(),
                    db: pool.clone(),
                    cache: if cache_enable.contains(&lookup_id) {
                        Mutex::new(LookupCache::new(
                            cache_entries,
                            cache_ttl_positive,
                            cache_ttl_negative,
                        ))
                        .into()
                    } else {
                        None
                    },
                })),
            );
        }

        Ok(())
    }
}