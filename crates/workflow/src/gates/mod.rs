//! Gates. The framework that turns evidence into an outcome is in [`framework`]. Each gate is a
//! directory owned by the package that writes it, and its module line is declared here so that
//! the owning package adds code without editing this file.

pub mod framework;

pub mod command;
pub mod dag;
pub mod docs;
pub mod readability;
pub mod scope;
pub mod spec;
pub mod supply_chain;
