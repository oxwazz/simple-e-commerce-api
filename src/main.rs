use actix_web::web::route;
use actix_web::{get, post, web, App, HttpResponse, HttpServer, Responder};
use dotenv::dotenv;
use serde::{Deserialize, Serialize};
use serde_with::serde_as;
use serde_with::DefaultOnNull;
use simple_e_commerce_api::utils::custom_validator::validate_url_if_exist;
use simple_e_commerce_api::utils::token_service;
use simple_e_commerce_api::utils::token_service::TokenService;
use sqlx::postgres::PgPoolOptions;
use sqlx::PgPool;
use std::{env, process};
use validator::{Validate, ValidationErrors};

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    dotenv().ok();

    let pool = PgPoolOptions::new()
        .max_connections(5)
        .connect("postgres://example:example@localhost:5433/example")
        .await
        .unwrap_or_else(|err| {
            eprintln!("Failed to create database pool: {}", err);
            process::exit(1)
        });
    println!("Actix running on http://localhost:8080");

    HttpServer::new(move || {
        App::new()
            .app_data(web::Data::new(token_service::TokenService::new()))
            .app_data(web::Data::new(pool.clone()))
            .route("/", web::get().to(greeting))
            .service(
                web::scope("/v1/auth")
                    // v1/auth/...
                    .route("/signup", web::post().to(signup)),
            )
    })
    .bind(("127.0.0.1", 8080))?
    .run()
    .await
}

#[serde_as]
#[derive(Serialize, Deserialize, Debug, Validate)]
#[serde(rename_all = "camelCase")]
struct SignupProps {
    #[serde(default)]
    #[serde_as(deserialize_as = "DefaultOnNull")]
    #[serde(skip_serializing)]
    name: String,
    #[validate(email)]
    email: String,
    // TODO: custom validation for password
    password: String,
    #[validate(custom(function = "validate_url_if_exist"))]
    #[serde(default)]
    #[serde_as(deserialize_as = "DefaultOnNull")]
    #[serde(skip_serializing_if = "String::is_empty")]
    image: String,
}

async fn greeting() -> impl Responder {
    HttpResponse::Ok().body("Hey there!")
}

async fn signup(
    t: web::Data<TokenService>,
    pool: web::Data<PgPool>,
    info: web::Json<SignupProps>,
) -> impl Responder {
    let hashed_password = bcrypt::hash("hunter2", bcrypt::DEFAULT_COST).unwrap_or_else(|err| {
        eprintln!("Failed hashed: {}", err);
        process::exit(1)
    });
    // let valid = bcrypt::verify("hunter2", &hashed_password).unwrap_or_else(|err| {
    //     eprintln!("Failed valid: {}", err);
    //     process::exit(1)
    // });
    // println!("{hashed_password} = {valid}");

    if let Err(err) = info.validate() {
        return HttpResponse::InternalServerError().json(serde_json::json!({
            "error": {
                "code": "ERR_FAILED_CREATE_USER",
                "message": "Failed to create user",
                "raw": err.to_string(),
            },
        }));
    };

    match sqlx::query(
        "INSERT INTO users(name, email, password, image, role) VALUES ($1, $2, $3, $4, $5);",
    )
    .bind(&info.name)
    .bind(&info.email)
    .bind(&hashed_password)
    .bind(&info.image)
    .bind("user")
    .execute(pool.get_ref())
    .await
    {
        Err(err) => {
            // Log the error (consider using a proper logging framework)
            // TODO: learn what is this
            tracing::error!("Failed to insert user: {}", err.to_string());

            // Return an appropriate error response
            HttpResponse::InternalServerError().json(serde_json::json!({
                "error": {
                    "code": "ERR_FAILED_CREATE_USER",
                    "message": "Failed to create user",
                    "raw": err.to_string(),
                },
            }))
        }
        Ok(_) => {
            // Successful insertion
            match t.create_tokens(&info.email, Some(info.email.clone()), "user") {
                Err(err) => {
                    // TODO: learn what is this
                    tracing::error!("Token creation failed: {}", err);
                    // Return an appropriate error response
                    HttpResponse::InternalServerError().json(serde_json::json!({
                        "error": {
                            "code": "ERR_FAILED_CREATE_JWT",
                            "message": "Failed to create jwt",
                            "raw": err.to_string(),
                        },
                    }))
                }
                Ok(token_pair) => HttpResponse::Ok().json(token_pair),
            }
        }
    }
}

//
// // Refresh token handler
// async fn refresh_token_handler(
//     token_service: web::Data<token_service::TokenService>,
//     refresh_token: web::Json<token_service::RefreshTokenRequest>,
// ) -> Result<HttpResponse, actix_web::Error> {
//     match token_service.refresh_access_token(&refresh_token.refresh_token) {
//         Ok(new_access_token) => Ok(HttpResponse::Ok().json(serde_json::json!({
//             "access_token": new_access_token
//         }))),
//         Err(_) => Err(actix_web::error::ErrorUnauthorized("Invalid refresh token")),
//     }
// }
