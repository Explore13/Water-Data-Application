CREATE TABLE users(
    id SERIAL PRIMARY KEY,
    user_name text NOT NULL,
    mobile_number BIGINT UNIQUE NOT NULL,
    city VARCHAR(20) NOT NULL,
    email VARCHAR(100) UNIQUE NOT NULL,
    password VARCHAR(100) NOT NULL
)