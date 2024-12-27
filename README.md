<p align="center">
    <picture>
        <source height="128" media="(prefers-color-scheme: dark)" srcset="https://github.com/tn3w/rusty-shield/releases/download/logo/rusty-logo-dark.png">
        <source height="128" media="(prefers-color-scheme: light)" srcset="https://github.com/tn3w/rusty-shield/releases/download/logo/rusty-logo-light.png">
        <img height="128" alt="Picture from Block Page" src="https://github.com/tn3w/rusty-shield/releases/download/logo/rusty-logo-light.png">
    </picture>
</p>
<h1 align="center">rusty-shield</h1>
<h6 align="center">A component of the Rusty toolbox designed for web application security: <a href="https://github.com/tn3w/rusty-loadbalancing">rusty-loadbalancing</a>, <a href="https://github.com/tn3w/rusty-shield">rusty-shield</a></h6>
<p align="center">An Actix-web middleware for checking IP addresses to identify unglobal, malicious, and TOR connections. It provides the browser with a zero-click Proof of Work (PoW) task, or, if JavaScript is disabled, a one-click CAPTCHA image challenge.</p>

## 🚀 Installing
Just add the following line to `[dependencies]` in your `Cargo.toml` file:
```toml
[dependencies]
rusty_shield = { git = "https://github.com/tn3w/rusty-shield" }
```

And then integrate the MiddleWare into your Actix-web app by registering it:

```rust
use actix_web::{web, App, HttpServer, HttpResponse};
use rusty_shield::{RequestValidationMiddleware, CookieMiddleware};

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    HttpServer::new(|| {
        App::new()
            //.wrap(RateLimitMiddleware) // Coming soon
            .wrap(RequestValidationMiddleware) // Register the request validation middleware
            .service(
                web::scope("")
                    .route("/", web::get().to(|| async { HttpResponse::Ok().body("Hello World!") }))
            )
            .wrap(CookieMiddleware)  // Register the cookie middleware after all services (required for RequestValidationMiddleware)
    })
    .bind("127.0.0.1:8080")?
    .run()
    .await
}
```

## Building
1. Install Rust using rust-up (optional): 
    ```bash
    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
    ```

2. Clone the git project:
    ```bash
    git clone https://github.com/tn3w/rusty-shield.git
    ```

3. Move into the project folder:
    ```bash
    cd rusty-shield
    ```

4. Setup Redis
    ```bash
    sudo apt-get update
    sudo apt-get install redis -y
    sudo systemctl enable redis-server.service
    sudo systemctl start redis-server.service
    ```

5. Install libssl-dev:
    ```bash
    sudo apt-get update
    sudo apt-get install libssl-dev -y
    ``` 

6. Build rusty-shield
    ```bash
    cargo build --release
    ```

### Attribution
- Logo icon: [Rust icons created by Freepik - Flaticon](https://www.flaticon.com/free-icons/rust)