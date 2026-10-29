//! Recompiles the crate when a migration is added or removed.
//!
//! `embed_migrations!` reads the files of the migrations it finds at compile time, but Cargo does
//! not watch the directory itself. Without this script a new migration does not reach a build
//! that already has the crate compiled: the start-up check then compares the database with an
//! older list than the repository has, and a database that is one migration behind is accepted.

fn main() {
    println!("cargo:rerun-if-changed=../../migrations");
}
