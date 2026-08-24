"""Domain services — the thin layer between HTTP routes and the datastore.

Motivation: route handlers were doing dedup, tallying, tier assignment, and
Store I/O inline. That put untestable business logic behind a TestClient and
made every route file ~300 loc of mixed concerns. Services fix both:

- Services own the ``Store`` interaction. They open it, do the work, close it,
  return plain data or raise domain exceptions. They do NOT know about HTTP.
- Routes own HTTP concerns: parse the body, validate at the boundary,
  translate service results into JSON, translate service exceptions into
  HTTPException, publish broker events for cross-tab live updates.

Test story: services are unit-tested against a temp db_path — no FastAPI, no
TestClient, no in-flight request. Routes stay small enough that a smoke test
of the happy path is sufficient.

Migration is lazy. New route work uses services from day one; existing routes
migrate when they're next touched substantively. The router files still work
unchanged during the migration.
"""
