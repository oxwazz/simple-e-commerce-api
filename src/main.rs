use actix_web::{web, App, HttpRequest, HttpResponse, HttpServer, Responder};
use dotenv::dotenv;
use serde::{Deserialize, Serialize};
use serde_with::serde_as;
use serde_with::DefaultOnNull;
use simple_e_commerce_api::utils::custom_validator::validate_url_if_exist;
use simple_e_commerce_api::utils::token_service;
use sqlx::postgres::PgPoolOptions;
use sqlx::{FromRow, PgPool};
use std::process;
use uuid::Uuid;
use validator::Validate;

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
                    .route("/signup", web::post().to(signup))
                    .route("/signin", web::post().to(signin))
                    .route("/me", web::get().to(me)),
            )
    })
    .bind(("127.0.0.1", 8080))?
    .run()
    .await
}

#[serde_as]
#[derive(Serialize, Deserialize, Debug, Validate)]
#[serde(rename_all = "camelCase")]
struct SignupReqBody {
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

#[derive(Debug, FromRow, Deserialize, Serialize)]
#[sqlx(rename_all = "camelCase")]
struct UsersTable {
    id: Uuid,
    name: String,
    email: String,
    email_verified: Option<chrono::DateTime<chrono::offset::Utc>>,
    #[serde(skip_serializing)]
    password: String,
    image: String,
    role: String,
}

#[derive(Debug, FromRow, Deserialize, Serialize)]
#[sqlx(rename_all = "camelCase")]
struct UsersTableReturn {
    id: Uuid,
    name: String,
    email: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    image: String,
    role: String,
}

impl From<UsersTable> for UsersTableReturn {
    fn from(user: UsersTable) -> Self {
        Self {
            id: user.id,
            name: user.name,
            email: user.email,
            image: user.image,
            role: user.role,
        }
    }
}

#[serde_as]
#[derive(Serialize, Deserialize, Debug, Validate)]
#[serde(rename_all = "camelCase")]
struct SigninReqBody {
    #[validate(email)]
    email: String,
    // TODO: custom validation for password
    password: String,
}

async fn greeting() -> impl Responder {
    HttpResponse::Ok().body("Hey there!")
}

async fn signup(
    t: web::Data<token_service::TokenService>,
    pool: web::Data<PgPool>,
    body: web::Json<SignupReqBody>,
) -> impl Responder {
    let hashed_password =
        bcrypt::hash(&body.password, bcrypt::DEFAULT_COST).unwrap_or_else(|err| {
            eprintln!("Failed hashed: {}", err);
            process::exit(1)
        });

    if let Err(err) = body.validate() {
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
    .bind(&body.name)
    .bind(&body.email)
    .bind(&hashed_password)
    .bind(&body.image)
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
            match t.create_tokens(&body.email, Some(body.email.clone()), "user") {
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

async fn signin(
    t: web::Data<token_service::TokenService>,
    pool: web::Data<PgPool>,
    body: web::Json<SigninReqBody>,
) -> impl Responder {
    if let Err(err) = body.validate() {
        return HttpResponse::InternalServerError().json(serde_json::json!({
            "error": {
                "code": "ERR_FAILED_CREATE_USER",
                "message": "Failed to create user",
                "raw": err.to_string(),
            },
        }));
    };

    match sqlx::query_as::<sqlx::Postgres, UsersTable>("SELECT * FROM users WHERE email = $1;")
        .bind(&body.email)
        .fetch_one(pool.get_ref())
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
        Ok(res_db) => {
            dbg!(&res_db);
            dbg!(&body);
            match bcrypt::verify(&body.password, &res_db.password) {
                Err(err) => {
                    return HttpResponse::InternalServerError().json(serde_json::json!({
                        "error": {
                            "code": "ERR_BCRYPT_PARSE",
                            "message": "xxx",
                            "raw": err.to_string(),
                        },
                    }))
                }
                Ok(is_password_valid) => {
                    if !is_password_valid {
                        return HttpResponse::InternalServerError().json(serde_json::json!({
                            "error": {
                                "code": "ERR_BCRYPT_FALSE",
                                "message": "xxx",
                                "raw": serde_json::Value::Null,
                            },
                        }));
                    }
                }
            }
            if let Err(err) = bcrypt::verify(&body.password, &res_db.password) {
                return HttpResponse::InternalServerError().json(serde_json::json!({
                    "error": {
                        "code": "ERR_FAILED_AUTHENTICATED_USER",
                        "message": "xxx",
                        "raw": err.to_string(),
                    },
                }));
            };
            // Successful insertion
            match t.create_tokens(&res_db.id.to_string(), Some(body.email.clone()), "user") {
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

async fn me(
    t: web::Data<token_service::TokenService>,
    pool: web::Data<PgPool>,
    request: HttpRequest,
) -> impl Responder {
    let req_headers = request.headers();

    let basic_auth_header = req_headers.get("Authorization");
    let basic_auth = basic_auth_header
        .unwrap()
        .to_str()
        .unwrap()
        .split(" ")
        .collect::<Vec<&str>>();
    if basic_auth.get(1).is_none() {
        return HttpResponse::InternalServerError().json(serde_json::json!({
            "error": {
                "code": "ERR_CANT_GET_AUTH",
                "message": "xxx",
                "raw": serde_json::Value::Null,
            },
        }));
    }

    let user_id = match t.verify_access_token(basic_auth[1]) {
        Err(err) => {
            return HttpResponse::InternalServerError().json(serde_json::json!({
                "error": {
                    "code": "ERR_XXX",
                    "message": "Failed to create user",
                    "raw": err.to_string(),
                },
            }))
        }
        Ok(v) => v.sub,
    };

    match sqlx::query_as::<sqlx::Postgres, UsersTable>("SELECT * FROM users WHERE id = $1::uuid;")
        .bind(&user_id)
        .fetch_one(pool.get_ref())
        .await
    {
        Err(err) => {
            // Log the error (consider using a proper logging framework)
            // TODO: learn what is this
            tracing::error!("Failed to insert user: {}", err.to_string());

            // Return an appropriate error response
            HttpResponse::InternalServerError().json(serde_json::json!({
                "error": {
                    "code": "ERR_XXX",
                    "message": "Failed to create user",
                    "raw": err.to_string(),
                },
            }))
        }
        Ok(res_db) => {
            dbg!(&res_db);
            // let tes: UsersTableReturn = serde_json::from_value(&res_db).unwrap();
            HttpResponse::Ok().json(Into::<UsersTableReturn>::into(res_db))
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
