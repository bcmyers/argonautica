extern crate a2;
extern crate actix_web;
extern crate dotenv;
extern crate env_logger;
#[macro_use]
extern crate failure;
extern crate futures;
extern crate futures_cpupool;
extern crate futures_timer;
extern crate serde;
#[macro_use]
extern crate serde_derive;
extern crate serde_json;

use std::collections::HashMap;
use std::env;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use a2::data::SecretKey;
use a2::{Hasher, Verifier};
use actix_web::http::Method;
use actix_web::middleware::Logger;
use actix_web::{server, App, AsyncResponder, Error, HttpMessage, HttpRequest, HttpResponse};
use futures::Future;
use futures_cpupool::CpuPool;
use futures_timer::Delay;

const MINIMUM_DURATION_IN_MILLIS: u64 = 400;

fn load_secret_key() -> Result<SecretKey, failure::Error> {
    let dotenv_path = env::current_dir()?.join("examples").join("example.env");
    dotenv::from_path(&dotenv_path).map_err(|e| format_err!("{}", e))?;
    let base64_encoded_secret_key = env::var("SECRET_KEY")?;
    Ok(SecretKey::from_base64_encoded_str(
        &base64_encoded_secret_key,
    )?)
}

struct State {
    cpu_pool: CpuPool,
    database: Arc<Mutex<HashMap<String, String>>>,
    hasher: Hasher,
    verifier: Verifier,
}

impl State {
    fn new(secret_key: SecretKey) -> State {
        State {
            cpu_pool: CpuPool::new(4),
            database: Arc::new(Mutex::new(HashMap::new())),
            hasher: {
                let mut hasher = Hasher::default();
                hasher.with_secret_key(&secret_key);
                hasher
            },
            verifier: {
                let mut verifier = Verifier::default();
                verifier.with_secret_key(&secret_key);
                verifier
            },
        }
    }
    fn cpu_pool(&self) -> CpuPool {
        self.cpu_pool.clone()
    }
    fn database_ptr(&self) -> Arc<Mutex<HashMap<String, String>>> {
        self.database.clone()
    }
    fn hasher(&self) -> Hasher {
        self.hasher.clone()
    }
    fn verifier(&self) -> Verifier {
        self.verifier.clone()
    }
}

fn database(req: HttpRequest<State>) -> HttpResponse {
    let database_ptr = req.state().database_ptr();
    let database = {
        match database_ptr.lock() {
            Ok(database) => (*database).clone(),
            Err(_) => return HttpResponse::InternalServerError().finish(),
        }
    };
    HttpResponse::Ok().json(database)
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct RegisterRequest {
    email: String,
    password: String,
}

fn register(req: HttpRequest<State>) -> Box<Future<Item = HttpResponse, Error = Error>> {
    let start = Instant::now();
    let cpu_pool = req.state().cpu_pool();
    let database_ptr = req.state().database_ptr();
    let mut hasher = req.state().hasher();
    req.json()
        .from_err()
        .and_then(move |register_request: RegisterRequest| {
            cpu_pool.spawn_fn(move || {
                let hash = hasher.with_password(&register_request.password).hash()?;
                Ok::<_, failure::Error>((hash, register_request))
            })
        })
        .and_then(move |(hash, register_request)| {
            let mut database = database_ptr.lock().map_err(|e| format_err!("{}", e))?;
            (*database).insert(register_request.email, hash);
            Ok(())
        })
        .then(move |result1| {
            let duration = match Duration::from_millis(MINIMUM_DURATION_IN_MILLIS)
                .checked_sub(start.elapsed())
            {
                Some(duration) => duration,
                None => Duration::from_millis(0),
            };
            Delay::new(duration).then(move |result2| {
                match result2 {
                    Ok(_) => (),
                    Err(_) => return Ok(HttpResponse::InternalServerError().finish()),
                }
                match result1 {
                    Ok(_) => (),
                    Err(_) => return Ok(HttpResponse::BadRequest().finish()),
                }
                Ok(HttpResponse::Created().finish())
            })
        })
        .responder()
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct VerifyRequest {
    email: String,
    password: String,
}

fn verify(req: HttpRequest<State>) -> Box<Future<Item = HttpResponse, Error = Error>> {
    let start = Instant::now();
    let cpu_pool = req.state().cpu_pool();
    let database_ptr = req.state().database_ptr();
    let mut verifier = req.state().verifier();
    req.json()
        .from_err()
        .and_then(move |verify_request: VerifyRequest| {
            let hash = {
                let database = database_ptr.lock().map_err(|e| format_err!("{}", e))?;
                database
                    .get(&verify_request.email)
                    .ok_or(format_err!("not in database"))?
                    .clone()
            };
            Ok::<_, failure::Error>((hash, verify_request))
        })
        .and_then(move |(hash, verify_request)| {
            cpu_pool.spawn_fn(move || {
                let is_valid = verifier
                    .with_hash(&hash)
                    .with_password(&verify_request.password)
                    .verify()?;
                Ok::<_, failure::Error>(is_valid)
            })
        })
        .then(move |result1| {
            let duration = match Duration::from_millis(MINIMUM_DURATION_IN_MILLIS)
                .checked_sub(start.elapsed())
            {
                Some(duration) => duration,
                None => Duration::from_millis(0),
            };
            Delay::new(duration).then(move |result2| {
                match result2 {
                    Ok(_) => (),
                    Err(_) => return Ok(HttpResponse::InternalServerError().finish()),
                }
                let is_valid = match result1 {
                    Ok(is_valid) => is_valid,
                    Err(_) => return Ok(HttpResponse::Unauthorized().finish()),
                };
                if !is_valid {
                    return Ok(HttpResponse::Unauthorized().finish());
                }
                Ok(HttpResponse::Ok().finish())
            })
        })
        .responder()
}

fn main() -> Result<(), failure::Error> {
    env::set_var("RUST_LOG", "actix_web=info");
    env_logger::init();
    let secret_key = load_secret_key()?;
    server::new(move || {
        App::with_state(State::new(secret_key.clone()))
            .middleware(Logger::new("Milliseconds to process request: %D"))
            .resource("/database", |r| r.method(Method::GET).f(database))
            .resource("/register", |r| r.method(Method::POST).f(register))
            .resource("/verify", |r| r.method(Method::POST).f(verify))
    }).bind("127.0.0.1:8080")?
        .run();
    Ok(())
}
