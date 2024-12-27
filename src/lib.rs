use std::collections::HashMap;
use std::future::{ready, Future, Ready};
use std::pin::Pin;
use futures_util::{future::LocalBoxFuture};
use actix_web::{
    cookie,
    dev::{
        forward_ready, Service, ServiceRequest,
        ServiceResponse, Transform
    },
    error::Error,
    http::header,
    body::MessageBody,
    HttpMessage,
    HttpResponse,
};
use actix_web::body::EitherBody;

mod utils;
mod ip_validator;
use ip_validator::IpChecker;
mod renderer;
use renderer::render_check;
mod captcha;
// TODO: Implement middleware that verifies the client's IP address and caches the results in Redis.
// TODO: If the IP address is identified as malicious or invalid, display the check.html page with the appropriate translations,
// TODO: along with the current proof-of-work state and challenge. If JavaScript is disabled, display captcha.html instead.
// TODO: The captcha.html page should be generated by loading AI-generated images from files at application startup.
// TODO: Each request will distort these images and store the correct versions along with a timestamp and the corresponding IP address
// TODO: for correlation purposes. All templates and AI datasets should be preloaded into memory at startup for efficient access.

const LANGUAGES: [&str; 107] = [
    "af", "sq", "am", "ar", "hy", "az", "eu", "be", "bn", "bs", "bg", "ca", "ceb", "ny",
    "zh-cn", "zh-tw", "co", "hr", "cs", "da", "nl", "en", "eo", "et", "tl", "fi", "fr",
    "fy", "gl", "ka", "de", "el", "gu", "ht", "ha", "haw", "iw", "he", "hi", "hmn", "hu",
    "is", "ig", "id", "ga", "it", "ja", "jw", "kn", "kk", "km", "ko", "ku", "ky", "lo",
    "la", "lv", "lt", "lb", "mk", "mg", "ms", "ml", "mt", "mi", "mr", "mn", "my", "ne",
    "no", "or", "ps", "fa", "pl", "pt", "pa", "ro", "ru", "sm", "gd", "sr", "st", "sn",
    "sd", "si", "sk", "sl", "so", "es", "su", "sw", "sv", "tg", "ta", "te", "th", "tr",
    "uk", "ur", "ug", "uz", "vi", "cy", "xh", "yi", "yo", "zu"
];

#[derive(Clone)]
pub struct RequestValidationMiddleware;


impl RequestValidationMiddleware {
    pub fn new() -> Self {
        Self
    }
}

impl<S, B> Transform<S, ServiceRequest> for RequestValidationMiddleware
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error> + Clone + 'static,
    S::Future: 'static,
    B: 'static + MessageBody,
{
    type Response = ServiceResponse<EitherBody<B>>;
    type Error = Error;
    type Transform = RequestValidationMiddlewareService<S>;
    type InitError = ();
    type Future = Ready<Result<Self::Transform, Self::InitError>>;

    fn new_transform(&self, service: S) -> Self::Future {
        ready(Ok(RequestValidationMiddlewareService { service }))
    }
}

pub struct RequestValidationMiddlewareService<S> {
    service: S,
}

impl<S, B> Service<ServiceRequest> for RequestValidationMiddlewareService<S>
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error> + Clone + 'static,
    S::Future: 'static,
    B: 'static + MessageBody,
{
    type Response = ServiceResponse<EitherBody<B>>;
    type Error = Error;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>>>>;

    forward_ready!(service);

    fn call(&self, req: ServiceRequest) -> Self::Future {
        let service = self.service.clone();

        Box::pin(async move {
            let ip = req
                .connection_info()
                .peer_addr()
                .unwrap_or("127.0.0.1")
                .to_string();

            let _user_agent = extract_header(&req, header::USER_AGENT, "");
            let preferred_lang = extract_language(&req);
            let selected_lang = LANGUAGES
                .iter()
                .find(|&&l| l == preferred_lang)
                .unwrap_or(&"en");

            let ip_checker = IpChecker::new("redis://127.0.0.1/")
                .expect("Failed to create IP checker");

            if let Some(reason) = ip_checker.is_ip_malicious(&ip).await {
                let error_page = render_check(selected_lang, req.uri().to_string(), reason);
                let res = HttpResponse::BadRequest()
                    .content_type("text/html")
                    .body(error_page);

                return Ok(ServiceResponse::new(
                    req.into_parts().0,
                    res.map_into_right_body::<B>(),
                ));
            }

            Ok(service.call(req).await?.map_into_left_body())
        })
    }
}

fn extract_header(req: &ServiceRequest, key: header::HeaderName, default: &str) -> String {
    req.headers()
        .get(key)
        .and_then(|h| h.to_str().ok())
        .unwrap_or(default)
        .to_string()
}

fn extract_language(req: &ServiceRequest) -> &str {
    req.headers()
        .get(header::ACCEPT_LANGUAGE)
        .and_then(|h| h.to_str().ok())
        .and_then(|lang| lang.split(',').next())
        .and_then(|l| l.split(';').next())
        .unwrap_or("en")
}

#[derive(Default)]
pub struct RequestCookies(HashMap<String, String>);

pub fn add_cookie(req: &ServiceRequest, key: String, value: String) {
    if let Some(cookies) = req.extensions_mut().get_mut::<RequestCookies>() {
        cookies.0.insert(key, value);
    } else {
        let mut cookies = RequestCookies::default();
        cookies.0.insert(key, value);
        req.extensions_mut().insert(cookies);
    }
}

pub struct CookieMiddleware;

impl CookieMiddleware {
    pub fn new() -> Self {
        Self
    }
}

impl<S, B> Transform<S, ServiceRequest> for CookieMiddleware
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error> + Clone + 'static,
    S::Future: 'static,
    B: 'static,
{
    type Response = ServiceResponse<B>;
    type Error = Error;
    type Transform = CookieMiddlewareService<S>;
    type InitError = ();
    type Future = Ready<Result<Self::Transform, Self::InitError>>;

    fn new_transform(&self, service: S) -> Self::Future {
        ready(Ok(CookieMiddlewareService { service }))
    }
}

pub struct CookieMiddlewareService<S> {
    service: S,
}


impl<S, B> Service<ServiceRequest> for CookieMiddlewareService<S>
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error> + Clone + 'static,
    S::Future: 'static,
    B: 'static,
{
    type Response = ServiceResponse<B>;
    type Error = Error;
    type Future = LocalBoxFuture<'static, Result<ServiceResponse<B>, Error>>;

    forward_ready!(service);

    fn call(&self, req: ServiceRequest) -> Self::Future {
        let service = self.service.clone();

        Box::pin(async move {
            let mut response = service.call(req).await?;

            let cookies_to_add: Vec<(String, String)> = if let Some(cookies) = response
                .request()
                .extensions()
                .get::<RequestCookies>()
            {
                cookies.0.iter()
                    .map(|(k, v)| (k.clone(), v.clone()))
                    .collect()
            } else {
                Vec::new()
            };

            for (key, value) in cookies_to_add {
                let cookie = cookie::Cookie::build(key, value)
                    .path("/")
                    .finish();
                response.response_mut().add_cookie(&cookie)?;
            }

            Ok(response)
        })
    }
}