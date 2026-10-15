-- Per-user, per-namespace opaque JSON store (GET/PUT /api/data/:namespace).
-- `data` is JSON text the server never inspects; `revision` is bumped on every write and
-- used for optimistic concurrency; `updated_at` is epoch milliseconds.

create table "app_data" ("user_id" text not null references "user" ("id") on delete cascade, "namespace" text not null, "data" text not null, "revision" integer not null, "updated_at" integer not null, primary key ("user_id", "namespace"));
