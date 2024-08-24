use actix_web::{web, App, HttpServer, HttpRequest, HttpResponse, Responder, post, get};
use actix_cors::Cors;
use serde::{Deserialize, Serialize};
use jsonwebtoken::{encode, decode, Header, Algorithm, EncodingKey, DecodingKey, Validation};
use bcrypt::{hash, verify, DEFAULT_COST};
use std::sync::Mutex;

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

struct AppState {
    users: Mutex<Vec<User>>,
}

#[post("/register")]
async fn register(user: web::Json<User>, data: web::Data<AppState>) -> impl Responder {
    let hashed_password = hash(&user.password, DEFAULT_COST).unwrap();
    let mut users = data.users.lock().unwrap();
    users.push(User {
        username: user.username.clone(),
        password: hashed_password,
    });
    HttpResponse::Ok().json("User registered successfully")
}

#[post("/login")]
async fn login(user: web::Json<User>, data: web::Data<AppState>) -> impl Responder {
    let users = data.users.lock().unwrap();
    for stored_user in users.iter() {
        if stored_user.username == user.username {
            if verify(&user.password, &stored_user.password).unwrap() {
                let my_claims = Claims {
                    sub: user.username.clone(),
                    exp: 10000000000,
                };
                let token = encode(&Header::default(), &my_claims, &EncodingKey::from_secret("secret".as_ref())).unwrap();
                return HttpResponse::Ok().json(token);
            }
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
    let app_state = web::Data::new(AppState {
        users: Mutex::new(Vec::new()),
    });

    HttpServer::new(move || {
        let cors = Cors::default()
            .allow_any_origin()
            .allow_any_method()
            .allow_any_header();

        App::new()
            .wrap(cors)
            .app_data(app_state.clone())
            .service(register)
            .service(login)
            .service(hello)
            .service(whazzup)
    })
    .bind("127.0.0.1:8080")?
    .run()
    .await
}