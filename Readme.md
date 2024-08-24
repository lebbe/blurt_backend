## Authentication

The authentication uses a jwt in the Authorization header.

It verifies the identity of the user itself, by refering to
the users ID in the database.

## Database tables

### users

- id: incremented
- username: unique string
- password_hash: the hashed password

### messages

- id: incremented
- user_id: id of user who posted
- message: the message posted

### subscriptions

- id: incremented
- from_id: id of the user that subscribes to another user
  -to_id: id of the user that is being subscribed to
