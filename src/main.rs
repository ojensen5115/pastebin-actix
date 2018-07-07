#![allow(unused_variables)]
#![cfg_attr(feature = "cargo-clippy", allow(needless_pass_by_value))]

#[macro_use] extern crate askama;
#[macro_use] extern crate lazy_static;
extern crate actix;
extern crate actix_web;
extern crate crypto;
extern crate bytes;
extern crate env_logger;
extern crate futures;
extern crate rand;
extern crate syntect;

use actix_web::http::{Method, StatusCode};
use actix_web::{
    middleware, pred, server, App, Path, HttpRequest, HttpMessage, HttpResponse, Result, FutureResponse, AsyncResponder
};

use askama::Template;

use crypto::hmac::Hmac;
use crypto::mac::Mac;
use crypto::sha2::Sha256;

use bytes::Bytes;

use futures::future::Future;

use rand::Rng;

use syntect::easy::HighlightLines;
use syntect::highlighting::{Theme, ThemeSet, Style};
use syntect::html::highlighted_snippet_for_string;
use syntect::parsing::SyntaxSet;
use syntect::util::as_24_bit_terminal_escaped;

use std::env;
use std::fs::File;
use std::io::Write;
//use std::path::Path;

const BASE62: &'static [u8] = b"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
const UPLOADS_DIR: &'static str = "uploads";
const ID_LEN: usize = 5;
const KEY_BYTES: usize = 8;
const MAX_PASTE_BYTES: usize = 2 * 1024 * 1024; // 2 MB
const PASTE_DAYS: u32 = 30; // u32 needed for Duration checked_mul()

lazy_static! {
    static ref HMAC_KEY: String = {
        String::from_utf8(std::fs::read("hmac_key.txt").expect("Reading HMAC key")).expect("Corrupt HMAC key")
    };
    static ref HL_THEME: Theme = {
        let ts = ThemeSet::load_defaults();
        let theme = &ts.themes["base16-eighties.dark"];
        theme.clone()
    };
}

// SyntaxSet does not implement Copy/Sync, so we do it like this.
// see https://github.com/trishume/syntect/issues/20
thread_local! {
    static SYNTAX_SET: SyntaxSet = SyntaxSet::load_defaults_nonewlines();
}

#[derive(Debug)]
enum HighlightedText {
    Terminal(String),
    Html(String),
    Error(String)
}

#[derive(Template)]
#[template(path = "index.html")]
struct IndexTemplate<'a> {
    host: &'a str,
    scheme: &'a str,
    id: &'a str,
    key: &'a str,
    ext: &'a str,
}

#[derive(Template)]
#[template(path = "help.html")]
struct HelpTemplate<'a> {
    host: &'a str,
    scheme: &'a str,
    id: &'a str,
    key: &'a str,
    ext: &'a str,
}

#[derive(Template)]
#[template(path = "paste_html.html")]
struct PasteTemplate<'a> {
    paste: &'a str,
}


// syntax highlighter helper function
fn highlight(buffer: String, lang: &str, html: bool) -> HighlightedText {
    SYNTAX_SET.with(|ss| {
        let syntax = ss.find_syntax_by_extension(lang).unwrap_or_else(|| ss.find_syntax_plain_text());
        if syntax.name == "Plain Text" {
            return HighlightedText::Error(format!("Requested highlight \"{}\" not available", lang));
        }
        if html {
            HighlightedText::Html(highlighted_snippet_for_string(&buffer, syntax, &HL_THEME))
        } else {
            let mut highlighter = HighlightLines::new(syntax, &HL_THEME);
            let mut output = String::new();
            for line in buffer.lines() {
                let ranges: Vec<(Style, &str)> = highlighter.highlight(line);
                let escaped;
                escaped = as_24_bit_terminal_escaped(&ranges[..], false);
                output += &format!("{}\n", escaped);
            }
            HighlightedText::Terminal(output)
        }
    })
}


fn generate_id(size: usize) -> String {
    let mut id = String::with_capacity(size);
    let mut rng = rand::thread_rng();
    for _ in 0..size {
        id.push(BASE62[rng.gen::<usize>() % 62] as char);
    }
    id
}

fn gen_key(input: &str) -> String {
    let mut hmac = Hmac::new(Sha256::new(), HMAC_KEY.as_bytes());
    hmac.input(input.as_bytes());
    let hmac_result = hmac.result();
    let key: String = hmac_result.code().iter()
        .take(KEY_BYTES)
        .map(|b| format!("{:02X}", b))
        .collect();
    key.to_lowercase()
}



/// usage template handler
fn usage(req: HttpRequest) -> Result<HttpResponse> {
    let s = IndexTemplate {
        host: req.connection_info().host(),
        scheme: req.connection_info().scheme(),
        id: "vxcRz",
        key: "a7772362cf6e2c36",
        ext: "rs",
    }.render().unwrap();

    Ok(HttpResponse::Ok().content_type("text/plain; charset=utf-8").body(s))
}

/// full usage template handler
fn help(req: HttpRequest) -> Result<HttpResponse> {
    // TODO: combine this with the usage handler if possible.
    let s = HelpTemplate {
        host: req.connection_info().host(),
        scheme: req.connection_info().scheme(),
        id: "vxcRz",
        key: "a7772362cf6e2c36",
        ext: "rs",
    }.render().unwrap();

    Ok(HttpResponse::Ok().content_type("text/plain; charset=utf-8").body(s))
}

/// paste retrieve handler
fn retrieve(req: HttpRequest) -> Result<HttpResponse> {
    let path = format!("uploads/{}", req.match_info().get("id").unwrap_or(""));
    match std::fs::read(path) {
        Ok(buffer) => {
            // able to open the file
            match req.match_info().get("aux") {
                Some(lang) => {
                    // syntax highlighting
                    let html_output = match req.headers().get("accept") {
                        Some(a) => a.to_str().unwrap_or("").contains("text/html"),
                        None    => false
                    };
                    match highlight(String::from_utf8_lossy(&buffer).to_string(), lang, html_output) {
                        HighlightedText::Terminal(s) => Ok(HttpResponse::build(StatusCode::OK)
                            .content_type("text/plain; charset=utf-8")
                            .body(s)),
                        HighlightedText::Html(s) => {
                            let rendered = PasteTemplate {
                                paste: &s
                            }.render().unwrap();
                            Ok(HttpResponse::build(StatusCode::OK)
                                .content_type("text/html; charset=utf-8")
                                .body(rendered))
                        },
                        HighlightedText::Error(s) => Ok(HttpResponse::BadRequest().content_type("text/plain; charset=utf-8").body(format!("Invalid request: {}.\n", s)))
                    }
                },
                None => {
                    // no syntax highlighting
                    Ok(HttpResponse::build(StatusCode::OK)
                        .content_type("text/plain; charset=utf-8")
                        .body(buffer))
                }
            }
        },
        Err(_) => Ok(HttpResponse::NotFound().content_type("text/plain; charset=utf-8").body("Not Found\n"))
    }
}

/// paste submission handler
fn submit(req: HttpRequest) -> FutureResponse<HttpResponse> {
    let base_url = format!("{scheme}://{host}", scheme = req.connection_info().scheme(), host = req.connection_info().host());
    req.body()
        .limit(MAX_PASTE_BYTES)
        .from_err()
        .and_then(move |bytes: Bytes| {
            // determine paste URL
            let mut id: String;
            let mut path: String;
            let mut double_id_len = ID_LEN * 2; // so we increase by 1 every two loops
            loop {
                id = generate_id(double_id_len / 2);
                path = format!("uploads/{id}", id = id);
                if !std::path::Path::new(&path).exists() {
                    break;
                }
                double_id_len += 1;
            }
            let url = format!("{base_url}/{id}", base_url = base_url, id = id);
            // write the file
            let mut f = File::create(path)?;
            f.write_all(&bytes)?;
            // return the response
            Ok(HttpResponse::Ok().body(format!(
                "View URL: {url}\nEdit URL: {url}/{key}\n\nThis paste will be deleted in {days} days.\n",
                url = url, key = gen_key(&id), days = PASTE_DAYS)).into())
        }).responder()
}

/// paste replace handler
fn replace(req: HttpRequest) -> FutureResponse<HttpResponse> {
    // TODO: it'd be nice if we could get the path info less suckily
    let id = req.match_info().get("id").unwrap_or("").to_string();
    let key = req.match_info().get("aux").unwrap_or("").to_string();

    // replace it with request data
    let base_url = format!("{scheme}://{host}", scheme = req.connection_info().scheme(), host = req.connection_info().host());
    let path = format!("{}/{}", UPLOADS_DIR, id);
    req.body()
        .limit(MAX_PASTE_BYTES)
        .from_err()
        .and_then(move |bytes: Bytes| {
            // verify key
            if key != gen_key(&id) {
                return Ok(HttpResponse::Unauthorized().content_type("text/plain; charset=utf-8").body("Unauthorized: Invalid key\n")).into();
            }
            let url = format!("{base_url}/{id}", base_url = base_url, id = id);
            // write the file
            let mut f = File::create(path)?;
            f.write_all(&bytes)?;
            // return the response
            Ok(HttpResponse::Ok().body(format!(
                "View URL: {url}\nEdit URL: {url}/{key}\n\nThis paste will be deleted in {days} days.\n",
                url = url, key = gen_key(&id), days = PASTE_DAYS)).into())
        }).responder()
}

/// paste deletion handler
fn delete(info: Path<(String, String)>) -> Result<HttpResponse> {
    let id = &info.0;
    let key = &info.1;
    if key != &gen_key(&id) {
        //return Ok(HttpResponse::Unauthorized().content_type("text/plain; charset=utf-8").body("Unauthorized: Invalid key\n"));
    }
    // delete file
    std::fs::remove_file(format!("{}/{}", UPLOADS_DIR, id))?;
    Ok(HttpResponse::Ok().content_type("text/plain; charset=utf-8").body("Paste deleted\n"))
}



fn main() {
    //env::set_var("RUST_BACKTRACE", "1");
    env::set_var("RUST_LOG", "actix_web=debug");
    env_logger::init();
    let sys = actix::System::new("pastebin-actix");

    let addr = server::new(
        || App::new()
            .middleware(middleware::Logger::default())
            .resource("/", |r| {
                r.get().f(usage);
                r.post().f(submit);
            })
            .resource("/help", |r| r.method(Method::GET).f(help))
            //.resource("/webupload", |r| r.method(Method::GET).f(webupload))
            .resource("/{id}", |r| r.method(Method::GET).f(retrieve))
            .resource("/{id}/{aux}", |r| {
                r.put().f(replace);
                r.get().with(retrieve);
                r.delete().with(delete);
            })

            .default_resource(|r| {
                r.method(Method::GET).f(|req|
                    HttpResponse::NotFound().content_type("text/plain; charset=utf-8").body("Not Found\n"));
                r.route().filter(pred::Not(pred::Get())).f(|req|
                    HttpResponse::BadRequest().content_type("text/plain; charset=utf-8").body("Bad Request\n"));
            }))

        .bind("127.0.0.1:8080").expect("Can not bind to 127.0.0.1:8080")
        .shutdown_timeout(0)    // <- Set shutdown timeout to 0 seconds (default 60s)
        .start();

    println!("Starting http server: 127.0.0.1:8080");
    let _ = sys.run();
}