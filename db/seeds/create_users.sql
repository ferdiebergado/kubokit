-- Active: 1746615904154@@127.0.0.1@5432@slim@public
INSERT INTO users (email,password_hash,metadata)
VALUES
('111@example.com', 'hashed111', '{"name":"john"}'),
('222@example.com', 'hashed222', '{"name":"jane"}'),
('333@example.com', 'hashed333', '{"name":"sue", "sex":"female"}');

INSERT INTO users (email,password_hash)
VALUES
('000@example.com', 'hashed000');

INSERT INTO users (email,password_hash,verified_at)
VALUES
('444@example.com', 'hashed444', NOW());
