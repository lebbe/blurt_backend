use actix_web::{web, App, HttpServer, HttpRequest, HttpResponse, Responder, Error, post, get, delete};
use actix_cors::Cors;
use serde::{Deserialize, Serialize};
use jsonwebtoken::{encode, decode, Header, Algorithm, EncodingKey, DecodingKey, Validation};
use bcrypt::{hash, verify, DEFAULT_COST};
use sqlx::postgres::PgPoolOptions;
use sqlx::postgres::PgPool;
use sqlx::FromRow;
use dotenv::dotenv;
use std::env;


// For the jwt token
#[derive(Debug, Serialize, Deserialize)]
struct Claims {
    sub: String, // This is typically used for the username or email
    user_id: i32, // Add the user ID here
    exp: usize,
}

#[derive(Debug, Serialize, Deserialize)]
struct User {
    username: String,
    password: String,
}

#[derive(FromRow)]
struct StoredUser {
    id: i32,
    username: String,
    password_hash: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct NewMessage {
    message: String,
}

#[derive(Debug, FromRow, Serialize)]
struct Message {
    id: i32,
    user_id: i32,
    message: String,
}

#[derive(Deserialize)]
struct Pagination {
    limit: Option<u32>,
    offset: Option<u32>,
}

impl Pagination {
    fn limit(&self) -> u32 {
        self.limit.unwrap_or(10)
    }

    fn offset(&self) -> u32 {
        self.offset.unwrap_or(0)
    }
}


#[post("/register")]
async fn register(user: web::Json<User>, pool: web::Data<sqlx::PgPool>) -> impl Responder {
    let hashed_password = hash(&user.password, DEFAULT_COST).unwrap();

    let result = sqlx::query!(
        r#"
        INSERT INTO users (username, password_hash)
        VALUES ($1, $2)
        RETURNING id
        "#,
        user.username,
        hashed_password
    )
    .fetch_one(pool.get_ref())
    .await;

    match result {
        Ok(_) => HttpResponse::Ok().json("User registered successfully"),
        Err(e) => HttpResponse::InternalServerError().body(format!("Failed to register user: {}", e)),
    }
}


#[post("/login")]
async fn login(user: web::Json<User>, pool: web::Data<sqlx::PgPool>) -> impl Responder {
    let result = sqlx::query_as!(
        StoredUser,
        r#"
        SELECT id, username, password_hash
        FROM users
        WHERE username = $1
        "#,
        user.username
    )
    .fetch_optional(pool.get_ref())
    .await;

    if let Ok(Some(stored_user)) = result {
        if verify(&user.password, &stored_user.password_hash).unwrap() {
            let my_claims = Claims {
                sub: user.username.clone(),
                user_id: stored_user.id, 
                exp: 10000000000,
            };
            let token = encode(&Header::default(), &my_claims, &EncodingKey::from_secret("secret".as_ref())).unwrap();
            return HttpResponse::Ok().json(token);
        }
    }

    HttpResponse::Unauthorized().json("Invalid username or password")
}


// Helper function to authorize requests
fn authorize_request(req: &HttpRequest) -> Result<Claims, Error> {
    let auth_header = req.headers().get("Authorization");

    if let Some(auth_value) = auth_header {
        if let Ok(auth_str) = auth_value.to_str() {
            if let Some(token) = auth_str.split_whitespace().nth(1) {
                let token_data = decode::<Claims>(
                    &token,
                    &DecodingKey::from_secret("secret".as_ref()),
                    &Validation::new(Algorithm::HS256),
                );

                if let Ok(data) = token_data {
                    return Ok(data.claims);
                }
            }
        }
    }

    let error_response = HttpResponse::Unauthorized().json("Unauthorized");
    Err(actix_web::error::InternalError::from_response("Unauthorized", error_response).into())
}


#[post("/message")]
async fn post_message(
    req: HttpRequest,
    pool: web::Data<sqlx::PgPool>,
    new_message: web::Json<NewMessage>,
) -> Result<HttpResponse, Error> {
    let claims = authorize_request(&req)?;

    let result = sqlx::query!(
        "INSERT INTO messages (user_id, message) VALUES ($1, $2) RETURNING id",
        claims.user_id, // Use the user ID from the JWT
        new_message.message
    )
    .fetch_one(pool.get_ref())
    .await;

    match result {
        Ok(record) => Ok(HttpResponse::Ok().json(record.id)),
        Err(e) => {
            let error_response = HttpResponse::InternalServerError().body(format!("Failed to create message: {}", e));
            Err(actix_web::error::InternalError::from_response("Database error", error_response).into())
        },
    }
}

#[delete("/message/{id}")]
async fn delete_message(
    req: HttpRequest,
    pool: web::Data<sqlx::PgPool>,
    message_id: web::Path<i32>,
) -> Result<HttpResponse, Error> {
    let claims = authorize_request(&req)?;

    let result = sqlx::query!(
        "DELETE FROM messages WHERE id = $1 AND user_id = $2",
        *message_id,
        claims.user_id // Use the user ID from the JWT
    )
    .execute(pool.get_ref())
    .await;

    match result {
        Ok(_) => Ok(HttpResponse::Ok().json("Message deleted successfully")),
        Err(e) => {
            let error_response = HttpResponse::InternalServerError().body(format!("Failed to delete message: {}", e));
            Err(actix_web::error::InternalError::from_response("Database error", error_response).into())
        },
    }
}

#[get("/messages/{user_id}")]
async fn get_messages(
    pool: web::Data<PgPool>,
    user_id: web::Path<i32>,
    pagination: web::Query<Pagination>,
) -> Result<HttpResponse, Error> {
    let raw_messages_result = sqlx::query!(
        "SELECT id, user_id, message FROM messages WHERE user_id = $1 LIMIT $2 OFFSET $3",
        *user_id,
        pagination.limit() as i64,
        pagination.offset() as i64
    )
    .fetch_all(pool.get_ref())
    .await;

    // Unwrap the Result and map the raw messages to the Message struct
    // return HttpResponse::Error if there is an error
    let raw_messages = raw_messages_result.map_err(|e| {
        let error_response = HttpResponse::InternalServerError().body(format!("Failed to fetch messages: {}", e));
        actix_web::error::InternalError::from_response("Database error", error_response)
    })?;

    let messages: Vec<Message> = raw_messages.into_iter().map(|raw_msg| {
        Message {
            id: raw_msg.id, // Provide a default value for id
            user_id: raw_msg.user_id.unwrap_or(0), // Provide a default value for user_id
            message: raw_msg.message, // Provide a default value for message
        }
    }).collect();

    Ok(HttpResponse::Ok().json(messages))
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    // Load the .env file
    dotenv().ok();
    // Load database URL from environment variable
    let database_url = env::var("DATABASE_URL").expect("DATABASE_URL must be set");

    // Create PostgreSQL connection pool
    let pool = PgPoolOptions::new()
        .max_connections(5)
        .connect(&database_url)
        .await
        .expect("Failed to create pool.");

    HttpServer::new(move || {
        let cors = Cors::default()
            .allow_any_origin() // TODO: Restrict origins
            .allow_any_method()
            .allow_any_header();

        App::new()
            .wrap(cors)
            .app_data(web::Data::new(pool.clone()))
            .service(register)
            .service(login)
            .service(post_message)
            .service(delete_message)
            .service(get_messages)
    })
    .bind("127.0.0.1:8080")?
    .run()
    .await
}
