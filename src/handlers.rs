use crate::auth::create_jwt;
use crate::models::{AuthRequest, AuthResponse, Claims, CreateProductRequest, Product, User, UserResponse};
use argon2::{
    password_hash::{rand_core::OsRng, PasswordHash, PasswordHasher, PasswordVerifier, SaltString},
    Argon2,
};
use poem::{
    handler,
    http::StatusCode,
    web::{Data, Json, Path},
    IntoResponse,
};
use sqlx::{Pool, Postgres};
use uuid::Uuid;

#[handler]
pub async fn register(
    db: Data<&Pool<Postgres>>,
    Json(req): Json<AuthRequest>,
) -> poem::Result<impl IntoResponse> {
    let salt = SaltString::generate(&mut OsRng);
    let argon2 = Argon2::default();
    let password_hash = argon2
        .hash_password(req.password.as_bytes(), &salt)
        .map_err(|_| poem::Error::from_status(StatusCode::INTERNAL_SERVER_ERROR))?
        .to_string();

    let user = sqlx::query_as::<_, User>(
        "INSERT INTO users (email, password_hash) VALUES ($1, $2) RETURNING *",
    )
    .bind(req.email)
    .bind(password_hash)
    .fetch_one(db.0)
    .await
    .map_err(|e| poem::Error::from_string(e.to_string(), StatusCode::BAD_REQUEST))?;

    let token = create_jwt(user.id.to_string(), user.role.clone())
        .map_err(|_| poem::Error::from_status(StatusCode::INTERNAL_SERVER_ERROR))?;

    Ok(Json(AuthResponse {
        token,
        user: UserResponse {
            id: user.id,
            email: user.email,
            role: user.role,
        },
    }))
}

#[handler]
pub async fn login(
    db: Data<&Pool<Postgres>>,
    Json(req): Json<AuthRequest>,
) -> poem::Result<impl IntoResponse> {
    let user = sqlx::query_as::<_, User>("SELECT * FROM users WHERE email = $1")
        .bind(req.email)
        .fetch_optional(db.0)
        .await
        .map_err(|e| poem::Error::from_string(e.to_string(), StatusCode::INTERNAL_SERVER_ERROR))?
        .ok_or_else(|| poem::Error::from_status(StatusCode::UNAUTHORIZED))?;

    let parsed_hash = PasswordHash::new(&user.password_hash)
        .map_err(|_| poem::Error::from_status(StatusCode::INTERNAL_SERVER_ERROR))?;

    Argon2::default()
        .verify_password(req.password.as_bytes(), &parsed_hash)
        .map_err(|_| poem::Error::from_status(StatusCode::UNAUTHORIZED))?;

    let token = create_jwt(user.id.to_string(), user.role.clone())
        .map_err(|_| poem::Error::from_status(StatusCode::INTERNAL_SERVER_ERROR))?;

    Ok(Json(AuthResponse {
        token,
        user: UserResponse {
            id: user.id,
            email: user.email,
            role: user.role,
        },
    }))
}

use poem::web::Query;
use crate::models::{SearchParams, PaginatedProducts};

#[handler]
pub async fn list_products(
    db: Data<&Pool<Postgres>>,
    Query(params): Query<SearchParams>,
) -> poem::Result<impl IntoResponse> {
    let limit = params.limit.unwrap_or(10);
    let page = params.page.unwrap_or(1);
    let offset = (page - 1) * limit;

    let search_query = format!("%{}%", params.q.unwrap_or_default());
    
    let products = sqlx::query_as::<_, Product>(
        r#"
        SELECT * FROM products 
        WHERE (name ILIKE $1 OR description ILIKE $1)
        AND ($2::UUID IS NULL OR category_id = $2)
        AND ($3::FLOAT8 IS NULL OR price >= $3)
        AND ($4::FLOAT8 IS NULL OR price <= $4)
        ORDER BY created_at DESC
        LIMIT $5 OFFSET $6
        "#,
    )
    .bind(search_query.clone())
    .bind(params.category)
    .bind(params.min_price)
    .bind(params.max_price)
    .bind(limit)
    .bind(offset)
    .fetch_all(db.0)
    .await
    .map_err(|e| poem::Error::from_string(e.to_string(), StatusCode::INTERNAL_SERVER_ERROR))?;

    let total: i64 = sqlx::query_scalar(
        r#"
        SELECT COUNT(*) FROM products 
        WHERE (name ILIKE $1 OR description ILIKE $1)
        AND ($2::UUID IS NULL OR category_id = $2)
        AND ($3::FLOAT8 IS NULL OR price >= $3)
        AND ($4::FLOAT8 IS NULL OR price <= $4)
        "#,
    )
    .bind(search_query)
    .bind(params.category)
    .bind(params.min_price)
    .bind(params.max_price)
    .fetch_one(db.0)
    .await
    .map_err(|e| poem::Error::from_string(e.to_string(), StatusCode::INTERNAL_SERVER_ERROR))?;

    Ok(Json(PaginatedProducts {
        data: products,
        total,
        page,
        last_page: (total as f64 / limit as f64).ceil() as i64,
    }))
}
#[handler]
pub async fn list_categories(db: Data<&Pool<Postgres>>) -> poem::Result<impl IntoResponse> {
    let categories = sqlx::query!("SELECT * FROM categories ORDER BY name ASC")
        .fetch_all(db.0)
        .await
        .map_err(|e| poem::Error::from_string(e.to_string(), StatusCode::INTERNAL_SERVER_ERROR))?;

    Ok(Json(categories))
}

#[handler]
pub async fn create_category(
    db: Data<&Pool<Postgres>>,
    claims: Data<&Claims>,
    Json(req): Json<serde_json::Value>,
) -> poem::Result<impl IntoResponse> {
    if claims.role != "admin" {
        return Err(poem::Error::from_status(StatusCode::FORBIDDEN));
    }

    let name = req["name"].as_str().ok_or_else(|| poem::Error::from_status(StatusCode::BAD_REQUEST))?;

    let category = sqlx::query!("INSERT INTO categories (name) VALUES ($1) RETURNING *", name)
        .fetch_one(db.0)
        .await
        .map_err(|e| poem::Error::from_string(e.to_string(), StatusCode::BAD_REQUEST))?;

    Ok(Json(category))
}

#[handler]
pub async fn create_product(
    db: Data<&Pool<Postgres>>,
    claims: Data<&Claims>,
    Json(req): Json<CreateProductRequest>,
) -> poem::Result<impl IntoResponse> {
    if claims.role != "admin" {
        return Err(poem::Error::from_status(StatusCode::FORBIDDEN));
    }

    let product = sqlx::query_as::<_, Product>(
        r#"
        INSERT INTO products (name, description, price, stock, image_url, category_id) 
        VALUES ($1, $2, $3, $4, $5, $6) 
        RETURNING *
        "#,
    )
    .bind(req.name)
    .bind(req.description)
    .bind(req.price)
    .bind(req.stock)
    .bind(req.image_url)
    .bind(req.category_id)
    .fetch_one(db.0)
    .await
    .map_err(|e| poem::Error::from_string(e.to_string(), StatusCode::INTERNAL_SERVER_ERROR))?;

    Ok(Json(product))
}

#[handler]
pub async fn delete_product(
    db: Data<&Pool<Postgres>>,
    claims: Data<&Claims>,
    Path(id): Path<Uuid>,
) -> poem::Result<impl IntoResponse> {
    if claims.role != "admin" {
        return Err(poem::Error::from_status(StatusCode::FORBIDDEN));
    }

    sqlx::query("DELETE FROM products WHERE id = $1")
        .bind(id)
        .execute(db.0)
        .await
        .map_err(|e| poem::Error::from_string(e.to_string(), StatusCode::INTERNAL_SERVER_ERROR))?;

    Ok(StatusCode::NO_CONTENT)
}
