//! Collections: named groups that tie exchanges, findings, and tasks together
//! (plan §F18 "collections/packs, links to tasks/findings").
//!
//! An organizer label (`exchange_label`) groups *exchanges* only. A collection is
//! the cross-cutting unit above that: one named bucket can hold exchanges, the
//! findings they produced, and the task that found them, so a tester can carry a
//! whole thread of work — "the IDOR on /orders" — as one object. Membership is a
//! set (a ref is in a collection at most once) keyed by `(collection, kind, ref)`,
//! and a collection is just a name plus its members, so deleting one never touches
//! the referenced rows.

use rusqlite::{params, Connection};

/// Schema for collections and their membership (additive migration v10→v11).
pub const SCHEMA: &str = "
CREATE TABLE IF NOT EXISTS collection (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    name          TEXT NOT NULL UNIQUE,
    note          TEXT,
    created_at_ms INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS collection_item (
    collection_id INTEGER NOT NULL,
    kind          TEXT NOT NULL,
    ref_id        INTEGER NOT NULL,
    added_at_ms   INTEGER NOT NULL,
    PRIMARY KEY (collection_id, kind, ref_id),
    FOREIGN KEY (collection_id) REFERENCES collection(id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_collection_item_ref ON collection_item(kind, ref_id);
";

/// What a collection member points at. Spelled lowercase in storage.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ItemKind {
    Exchange,
    Finding,
    Task,
}

impl ItemKind {
    /// Stored spelling.
    pub fn as_str(self) -> &'static str {
        match self {
            ItemKind::Exchange => "exchange",
            ItemKind::Finding => "finding",
            ItemKind::Task => "task",
        }
    }

    /// Parse a stored/CLI spelling (case-insensitive, tolerant of a plural).
    pub fn parse(s: &str) -> Option<Self> {
        match s.trim().to_ascii_lowercase().as_str() {
            "exchange" | "exchanges" => Some(ItemKind::Exchange),
            "finding" | "findings" => Some(ItemKind::Finding),
            "task" | "tasks" => Some(ItemKind::Task),
            _ => None,
        }
    }
}

/// A collection row with its current member count.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Collection {
    pub id: i64,
    pub name: String,
    pub note: Option<String>,
    pub created_at_ms: i64,
    pub item_count: i64,
}

/// One member of a collection.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CollectionItem {
    pub kind: ItemKind,
    pub ref_id: i64,
    pub added_at_ms: i64,
}

/// Create a collection (or return the id of the existing one with that name).
pub fn create(conn: &Connection, name: &str, at_ms: i64) -> rusqlite::Result<i64> {
    let name = name.trim();
    conn.execute(
        "INSERT INTO collection (name, created_at_ms) VALUES (?1, ?2)
         ON CONFLICT(name) DO NOTHING",
        params![name, at_ms],
    )?;
    conn.query_row(
        "SELECT id FROM collection WHERE name = ?1",
        params![name],
        |r| r.get(0),
    )
}

/// Add one member to a collection (idempotent — a repeat is a no-op).
pub fn add_item(
    conn: &Connection,
    collection_id: i64,
    kind: ItemKind,
    ref_id: i64,
    at_ms: i64,
) -> rusqlite::Result<bool> {
    let n = conn.execute(
        "INSERT INTO collection_item (collection_id, kind, ref_id, added_at_ms)
         VALUES (?1, ?2, ?3, ?4)
         ON CONFLICT(collection_id, kind, ref_id) DO NOTHING",
        params![collection_id, kind.as_str(), ref_id, at_ms],
    )?;
    Ok(n > 0)
}

/// Remove one member. Returns whether a row was removed.
pub fn remove_item(
    conn: &Connection,
    collection_id: i64,
    kind: ItemKind,
    ref_id: i64,
) -> rusqlite::Result<bool> {
    let n = conn.execute(
        "DELETE FROM collection_item
         WHERE collection_id = ?1 AND kind = ?2 AND ref_id = ?3",
        params![collection_id, kind.as_str(), ref_id],
    )?;
    Ok(n > 0)
}

/// List collections, newest first, each with its member count.
pub fn list(conn: &Connection) -> rusqlite::Result<Vec<Collection>> {
    let mut stmt = conn.prepare(
        "SELECT c.id, c.name, c.note, c.created_at_ms,
                (SELECT COUNT(*) FROM collection_item i WHERE i.collection_id = c.id)
         FROM collection c ORDER BY c.id DESC",
    )?;
    let rows = stmt.query_map([], |r| {
        Ok(Collection {
            id: r.get(0)?,
            name: r.get(1)?,
            note: r.get(2)?,
            created_at_ms: r.get(3)?,
            item_count: r.get(4)?,
        })
    })?;
    rows.collect()
}

/// Members of a collection, in insertion order.
pub fn items(conn: &Connection, collection_id: i64) -> rusqlite::Result<Vec<CollectionItem>> {
    let mut stmt = conn.prepare(
        "SELECT kind, ref_id, added_at_ms FROM collection_item
         WHERE collection_id = ?1 ORDER BY added_at_ms ASC, ref_id ASC",
    )?;
    let rows = stmt.query_map(params![collection_id], |r| {
        let kind: String = r.get(0)?;
        Ok(CollectionItem {
            kind: ItemKind::parse(&kind).unwrap_or(ItemKind::Exchange),
            ref_id: r.get(1)?,
            added_at_ms: r.get(2)?,
        })
    })?;
    rows.collect()
}

/// Delete a collection and (via cascade) its membership. Returns whether it
/// existed. The referenced exchanges/findings/tasks are untouched.
pub fn delete(conn: &Connection, collection_id: i64) -> rusqlite::Result<bool> {
    let n = conn.execute(
        "DELETE FROM collection WHERE id = ?1",
        params![collection_id],
    )?;
    Ok(n > 0)
}

/// Resolve a collection id by name.
pub fn id_by_name(conn: &Connection, name: &str) -> rusqlite::Result<Option<i64>> {
    use rusqlite::OptionalExtension;
    conn.query_row(
        "SELECT id FROM collection WHERE name = ?1",
        params![name.trim()],
        |r| r.get(0),
    )
    .optional()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Store;

    #[test]
    fn create_is_idempotent_by_name() {
        let store = Store::open_in_memory().unwrap();
        let a = store.collection_create("idor on /orders").unwrap();
        let b = store.collection_create("idor on /orders").unwrap();
        assert_eq!(a, b);
        assert_eq!(store.collections().unwrap().len(), 1);
    }

    #[test]
    fn members_span_kinds_and_dedupe() {
        let store = Store::open_in_memory().unwrap();
        let id = store.collection_create("thread").unwrap();
        assert!(store.collection_add(id, ItemKind::Exchange, 10).unwrap());
        assert!(store.collection_add(id, ItemKind::Finding, 3).unwrap());
        assert!(store.collection_add(id, ItemKind::Task, 1).unwrap());
        // Adding the same ref again is a no-op.
        assert!(!store.collection_add(id, ItemKind::Exchange, 10).unwrap());
        let items = store.collection_items(id).unwrap();
        assert_eq!(items.len(), 3);
        // The count is reflected in the listing.
        assert_eq!(store.collections().unwrap()[0].item_count, 3);
    }

    #[test]
    fn remove_and_delete_do_not_touch_referenced_rows() {
        let store = Store::open_in_memory().unwrap();
        let id = store.collection_create("c").unwrap();
        store.collection_add(id, ItemKind::Exchange, 5).unwrap();
        store.collection_add(id, ItemKind::Finding, 6).unwrap();
        assert!(store.collection_remove(id, ItemKind::Exchange, 5).unwrap());
        assert_eq!(store.collection_items(id).unwrap().len(), 1);
        // Deleting the collection cascades its membership away.
        assert!(store.collection_delete(id).unwrap());
        assert!(store.collections().unwrap().is_empty());
    }

    #[test]
    fn id_by_name_resolves() {
        let store = Store::open_in_memory().unwrap();
        let id = store.collection_create("named").unwrap();
        assert_eq!(store.collection_id("named").unwrap(), Some(id));
        assert_eq!(store.collection_id("missing").unwrap(), None);
    }
}
