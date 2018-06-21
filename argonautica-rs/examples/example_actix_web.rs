/// Toy example of an actix-web server that has endpoints for hashing and verifying passwords
extern crate actix_web;
extern crate argonautica;
extern crate dotenv;
extern crate env_logger;
#[macro_use]
extern crate failure;
extern crate futures;
extern crate futures_cpupool;
extern crate futures_timer;
#[macro_use]
extern crate serde;
extern crate serde_json;

use std::collections::HashMap;
use std::env;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use actix_web::http::Method;
use actix_web::middleware::Logger;
use actix_web::{server, App, AsyncResponder, Error, HttpMessage, HttpRequest, HttpResponse};
use argonautica::input::SecretKey;
use argonautica::{Hasher, Verifier};
use futures::Future;
use futures_cpupool::CpuPool;
use futures_timer::Delay;

// This will be used for the register and verify routes. We want these routes to take a
// at least a minimum amount of time to load since we don't want to give potential attackers
// any insight into what our code does with invalid inputs
const MINIMUM_DURATION_IN_MILLIS: u64 = 400;

// Helper method to load the secret key from a .env file. Used in `main` below.
fn load_secret_key() -> Result<SecretKey<'static>, failure::Error> {
    let dotenv_path = env::current_dir()?.join("examples").join("example.env");
    dotenv::from_path(&dotenv_path).map_err(|e| format_err!("{}", e))?;
    let base64_encoded_secret_key = env::var("SECRET_KEY")?;
    Ok(SecretKey::from_base64_encoded(
        &base64_encoded_secret_key,
    )?)
}

// "Global" state that will be passed to every call to a handler. Here we include the "database",
// which for example purposes is just a HashMap (but in real life would probably be Postgres
// or something of the sort), as well as instances of our Hasher and Verifier, which we "preload"
// with our secret key
struct State<'a> {
    database: Arc<Mutex<HashMap<String, String>>>,
    hasher: Hasher<'a>,
    verifier: Verifier<'a>,
}

impl<'a> State<'a> {
    // Since actix-web uses futures extensively, let's have the Hasher and Verifier
    // share a common CpuPool.  In addition, as mentioned above, we "preload" the Hasher and
    // Verifier with our secret key; so we only have to do this once (at creation of the
    // server in 'main')
    fn new(secret_key: &SecretKey<'a>) -> State<'static> {
        let cpu_pool = CpuPool::new(4);
        State {
            database: Arc::new(Mutex::new(HashMap::new())),
            hasher: {
                let mut hasher = Hasher::default();
                hasher
                    .configure_cpu_pool(cpu_pool.clone())
                    .with_secret_key(secret_key.to_owned());
                hasher
            },
            verifier: {
                let mut verifier = Verifier::default();
                verifier
                    .configure_cpu_pool(cpu_pool)
                    .with_secret_key(secret_key.to_owned());
                verifier
            },
        }
    }
    fn database_ptr(&self) -> Arc<Mutex<HashMap<String, String>>> {
        self.database.clone()
    }
    fn hasher(&self) -> Hasher<'static> {
        self.hasher.to_owned()
    }
    fn verifier(&self) -> Verifier<'static> {
        self.verifier.to_owned()
    }
}

// Handler for the "/database" route. This just returns a copy of the "database" (in json)
// In real life, you would obviously restrict access to this route to admins only
// or something of the sort, but in this example the routes is open to anyone
fn database(req: HttpRequest<State<'static>>) -> HttpResponse {
    let database_ptr = req.state().database_ptr();
    let database = {
        match database_ptr.lock() {
            Ok(database) => database,
            Err(_) => return HttpResponse::InternalServerError().finish(),
        }
    };
    HttpResponse::Ok().json(&*database)
}

// Struct representing the json object clients will need to provide when making
// a POST request to the "/register" route
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct RegisterRequest {
    email: String,
    password: String,
}

// Handler for the "/register" route. First we parse the client-provided json.
// Then we hash the password they provided using argonautica.  Next we add the email they
// provided and the hash to our "database". Finally, if all worked correctly, we
// return an empty 201 Created response. Note that we would like to
// ensure that calling this route always takes at least a minimum amount of time
// (to prevent attackers from gaining insight into our code); so at the end, we also
// delay before returning if the function has taken less than the minimum required amount
// of time.
fn register(req: HttpRequest<State<'static>>) -> Box<Future<Item = HttpResponse, Error = Error>> {
    let start = Instant::now();
    let database_ptr = req.state().database_ptr();
    let mut hasher = req.state().hasher();
    req.json()
        .map_err(|e| e.into())
        .and_then(move |register_request: RegisterRequest| {
            hasher
                .with_password(register_request.password.clone())
                .hash_non_blocking()
                .map_err(|e| e.into())
                // Futures are kind finicky; so let's map the result of our
                // call to hasher_non_blocking (which, if successful, is just a String)
                // to a tuple that includes both the resulting String and the original
                // RegisterRequest. This is needed for us to be able to access
                // the RegisterRequest in the next and_then block
                .map(|hash| (hash, register_request))
        })
        .and_then(move |(hash, register_request)| {
            let mut database = database_ptr.lock().map_err(|e| format_err!("{}", e))?;
            (*database).insert(register_request.email, hash);
            Ok::<_, failure::Error>(())
        })
        .then(move |result1| {
            let duration = Duration::from_millis(MINIMUM_DURATION_IN_MILLIS)
                .checked_sub(start.elapsed())
                .unwrap_or_else(|| Duration::from_millis(0));
            Delay::new(duration).then(move |result2| {
                if result1.is_err() {
                    return Ok(HttpResponse::BadRequest().finish());
                }
                if result2.is_err() {
                    return Ok(HttpResponse::InternalServerError().finish());
                }
                Ok(HttpResponse::Created().finish())
            })
        })
        .responder()
}

// Struct representing the json object clients will need to provide when making
// a POST request to the "/verify" route
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct VerifyRequest {
    email: String,
    password: String,
}

// Handler for the "/verify" routes. First we parse the client-provided json.
// Then we look up the client's hash in the "database" using the email they provided.
// Next we verify the password they provided against the hash we pulled from the
// "database". Finally, if all worked correctly, we return an empty 200 OK response
// to indicate that the password provided did indeed match the hash in our "database".
// As with the "/register" method above, we would like to ensure that calling this route
// always takes at least a minimum amount of time (to prevent attackers from gaining insight
// into our code); so we use the same trick with the `futures_timer` crate to ensure that here.
fn verify(req: HttpRequest<State<'static>>) -> Box<Future<Item = HttpResponse, Error = Error>> {
    let start = Instant::now();
    let database_ptr = req.state().database_ptr();
    let mut verifier = req.state().verifier();
    req.json()
        .map_err(|e| e.into())
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
            verifier
                .with_hash(&hash)
                .with_password(verify_request.password.clone())
                .verify_non_blocking()
                .map_err(|e| e.into())
        })
        .then(move |result1| {
            let duration = Duration::from_millis(MINIMUM_DURATION_IN_MILLIS)
                .checked_sub(start.elapsed())
                .unwrap_or_else(|| Duration::from_millis(0));
            Delay::new(duration).then(move |result2| {
                if result2.is_err() {
                    return Ok(HttpResponse::InternalServerError().finish());
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

// Main function to kick off the server and provide a small logging middleware
// that will print to stdout the amount of time that each request took to process
fn main() -> Result<(), failure::Error> {
    env::set_var("RUST_LOG", "actix_web=info");
    env_logger::init();
    let secret_key = load_secret_key()?;
    server::new(move || {
        App::with_state(State::new(&secret_key))
            .middleware(Logger::new("Milliseconds to process request: %D"))
            .resource("/database", |r| r.method(Method::GET).f(database))
            .resource("/register", |r| r.method(Method::POST).f(register))
            .resource("/verify", |r| r.method(Method::POST).f(verify))
    }).bind("127.0.0.1:8080")?
        .run();
    Ok(())
}
