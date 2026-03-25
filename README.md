# semitexa/auth

User authentication with credential flows, sessions, and pluggable auth handlers.

## Purpose

Manages request-level authentication. Discovers auth handlers via `#[AsAuthHandler]`, chains them per strategy (first_match, collect, required), and stores the authenticated principal in coroutine-safe context.

## Role in Semitexa

Depends on `semitexa/core`. Depended on by `semitexa/authorization`, `semitexa/api`, and platform packages. Auth resolves identity; access control decisions are delegated to downstream packages.

## Key Features

- `#[AsAuthHandler]` attribute for automatic handler discovery
- Strategy-based handler chaining: first_match, collect, required
- `AuthBootstrapper` orchestrating per-request authentication
- Coroutine-safe `AuthContextStore` for Swoole environments
- `SessionAuthHandler` as the default implementation
- `AuthenticatableInterface` contract for principal types

## Notes

Auth resolves identity only. Access control decisions are handled by `semitexa/authorization`.
