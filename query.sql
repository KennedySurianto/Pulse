
-- TO INSERT: username, password_hash
CREATE TABLE users (
	user_id SERIAL PRIMARY KEY,
	username VARCHAR(20) NOT NULL UNIQUE,
	password_hash VARCHAR(255) NOT NULL,
	profile_image_url VARCHAR(255) NOT NULL DEFAULT 'https://picsum.photos/200',
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- TO INSERT: user_id, friend_id
CREATE TABLE friends (
	user_id INT NOT NULL REFERENCES users(user_id) ON DELETE CASCADE,
	friend_id INT NOT NULL REFERENCES users(user_id) ON DELETE CASCADE,
	PRIMARY KEY (user_id, friend_id)
);

-- TO INSERT: chats (chat_id) VALUES (DEFAULT)
CREATE TABLE chats (
	chat_id SERIAL PRIMARY KEY,
	created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- TO INSERT: chat_id, group_name, group_image_url
CREATE TABLE groups (
	chat_id INT NOT NULL UNIQUE REFERENCES chats(chat_id) ON DELETE CASCADE,
	group_name VARCHAR(20) NOT NULL,
	group_image_url VARCHAR(255) NOT NULL DEFAULT 'https://picsum.photos/200'
);

-- TO INSERT: chat_id, user_id
CREATE TABLE group_leaders (
	chat_id INT NOT NULL REFERENCES chats(chat_id) ON DELETE CASCADE,
	user_id INT NOT NULL REFERENCES users(user_id) ON DELETE CASCADE,
	PRIMARY KEY (chat_id, user_id)
);

-- TO INSERT: chat_id, user_id
CREATE TABLE participants (
	chat_id INT NOT NULL REFERENCES chats(chat_id) ON DELETE CASCADE,
	user_id INT NOT NULL REFERENCES users(user_id) ON DELETE CASCADE,
	PRIMARY KEY (chat_id, user_id)
);

-- TO INSERT: content, chat_id, sender_id
CREATE TABLE messages (
	message_id SERIAL PRIMARY KEY,
	content TEXT NOT NULL,
	created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
	chat_id INT NOT NULL REFERENCES chats(chat_id) ON DELETE CASCADE,
	sender_id INT NOT NULL REFERENCES users(user_id) ON DELETE CASCADE
);
