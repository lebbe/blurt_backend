use actix_web::{web, App, HttpServer, HttpRequest, HttpResponse, Responder, post, get};
use actix_cors::Cors;
use serde::{Deserialize, Serialize};
use jsonwebtoken::{encode, decode, Header, Algorithm, EncodingKey, DecodingKey, Validation};
use bcrypt::{hash, verify, DEFAULT_COST};
use sqlx::postgres::PgPoolOptions;
use sqlx::FromRow;
use dotenv::dotenv;
use std::env;

#[derive(Debug, Serialize, Deserialize)]
struct Claims {
    sub: String,
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
                exp: 10000000000,
            };
            let token = encode(&Header::default(), &my_claims, &EncodingKey::from_secret("secret".as_ref())).unwrap();
            return HttpResponse::Ok().json(token);
        }
    }

    HttpResponse::Unauthorized().json("Invalid username or password")
}


// Helper function to authorize requests
fn authorize_request(req: &HttpRequest) -> Result<Claims, HttpResponse> {
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

    Err(HttpResponse::Unauthorized().json("Unauthorized"))
}

#[get("/hello")]
async fn hello(req: HttpRequest) -> impl Responder {
    match authorize_request(&req) {
        Ok(_claims) => HttpResponse::Ok().json("Hello, world!"),
        Err(error) => error,
    }
}

#[get("/whazzup")]
async fn whazzup(req: HttpRequest) -> impl Responder {
    match authorize_request(&req) {
        Ok(_claims) => HttpResponse::Ok().json("Whazzup!"),
        Err(error) => error,
    }
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
            .allow_any_origin()
            .allow_any_method()
            .allow_any_header();

        App::new()
            .wrap(cors)
            .app_data(web::Data::new(pool.clone()))
            .service(register)
            .service(login)
            .service(hello)
            .service(whazzup)
    })
    .bind("127.0.0.1:8080")?
    .run()
    .await
}