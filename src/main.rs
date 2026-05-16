mod auth;
mod handlers;
mod models;

use auth::AuthMiddleware;
use poem::{
    listener::TcpListener,
    middleware::{Cors, AddData},
    EndpointExt, Route, Server,
};
use sqlx::postgres::PgPoolOptions;
use std::env;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    dotenvy::dotenv().ok();

    let database_url = env::var("DATABASE_URL").expect("DATABASE_URL must be set");
    let pool = PgPoolOptions::new()
        .max_connections(5)
        .connect(&database_url)
        .await?;

    // Create routes
    let auth_routes = Route::new()
        .at("/register", poem::post(handlers::register))
        .at("/login", poem::post(handlers::login));

    let product_routes = Route::new()
        .at("/", poem::get(handlers::list_products).post(handlers::create_product))
        .at("/:id", poem::delete(handlers::delete_product))
        .with(AuthMiddleware);

    let category_routes = Route::new()
        .at("/", poem::get(handlers::list_categories).post(handlers::create_category))
        .with(AuthMiddleware);

    let app = Route::new()
        .nest("/api/auth", auth_routes)
        .nest("/api/products", product_routes)
        .nest("/api/categories", category_routes)
        .with(Cors::new())
        .with(AddData::new(pool));

    let port = env::var("PORT").unwrap_or_else(|_| "8080".to_string());
    let addr = format!("0.0.0.0:{}", port);

    println!("🚀 Backend running at http://{}", addr);

    Server::new(TcpListener::bind(addr))
        .run(app)
        .await?;

    Ok(())
}
