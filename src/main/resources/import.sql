INSERT INTO tb_user (email, password) VALUES ('maria@gmail.com', '$2a$10$QE1.ACGKoG3xdRowW8Zqp.Jk/6os8yb0qS5/wKSz5670/kUamLMkS');
INSERT INTO tb_user (email, password) VALUES ('alex@gmail.com', '$2a$10$QE1.ACGKoG3xdRowW8Zqp.Jk/6os8yb0qS5/wKSz5670/kUamLMkS');

INSERT INTO tb_role (authority) VALUES ('ROLE_CLIENT');
INSERT INTO tb_role (authority) VALUES ('ROLE_ADMIN');

INSERT INTO tb_user_role(user_id, role_id) VALUES (1, 1);
INSERT INTO tb_user_role(user_id, role_id) VALUES (2, 1);
INSERT INTO tb_user_role(user_id, role_id) VALUES (2, 2);