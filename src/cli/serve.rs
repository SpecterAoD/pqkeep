//! DE: `keyforge serve`: Token anlegen oder REST-API starten (Feature `api`).
//! Standard-Bind 127.0.0.1:8787; andere Adressen nur mit `--allow-remote` und Warnung.
//! EN: `keyforge serve`: create a token or start the REST API (feature `api`).
//! Default bind 127.0.0.1:8787; other addresses only with `--allow-remote` and a warning.

use std::net::SocketAddr;
use std::path::PathBuf;

use clap::{Arg, ArgAction, ArgMatches, Command, value_parser};
use pqc_keyforge::api::{self, AppState, Limits, TokenHash, token};
use pqc_keyforge::envelope::Overwrite;
use pqc_keyforge::hardening::sandbox::Profile;
use pqc_keyforge::security::Lang;

use super::io::{CliResult, Failure, code};
use super::sandbox;
use super::serve_text::serve_texts;

/// DE: Standardadresse. EN: Default address.
pub const DEFAULT_BIND: &str = "127.0.0.1:8787";

/// DE: Argumente von `serve` (an das gemeinsame Grundgerüst angehängt).
/// EN: Arguments of `serve` (appended to the shared base command).
pub fn command(base: Command, lang: Lang) -> Command {
    let s = serve_texts(lang);
    let flag = |name: &'static str, help: &'static str| {
        Arg::new(name)
            .long(name)
            .help(help)
            .action(ArgAction::SetTrue)
    };
    base.arg(
        Arg::new("token-file")
            .long("token-file")
            .help(s.arg_token_file)
            .required(true)
            .value_parser(value_parser!(PathBuf)),
    )
    .arg(
        Arg::new("bind")
            .long("bind")
            .help(s.arg_bind)
            .default_value(DEFAULT_BIND)
            .hide_default_value(true),
    )
    .arg(flag("allow-remote", s.arg_allow_remote))
    .arg(flag("init-token", s.arg_init_token))
    .arg(flag("force", s.arg_force).requires("init-token"))
}

/// DE: `keyforge serve`. EN: `keyforge serve`.
pub fn serve(lang: Lang, m: &ArgMatches, sandboxed: bool) -> CliResult {
    let s = serve_texts(lang);
    let path = m
        .get_one::<PathBuf>("token-file")
        .ok_or_else(|| Failure::new(code::USAGE, ""))?;
    if m.get_flag("init-token") {
        let overwrite = if m.get_flag("force") {
            Overwrite::Yes
        } else {
            Overwrite::No
        };
        let token = token::create(path, overwrite).map_err(|e| Failure::from_error(&e, lang))?;
        eprintln!("{}", s.msg_token_created);
        println!("{}", token.as_str());
        return Ok(());
    }
    let addr: SocketAddr = m
        .get_one::<String>("bind")
        .and_then(|b| b.parse().ok())
        .ok_or_else(|| Failure::new(code::USAGE, s.msg_bad_bind))?;
    if !addr.ip().is_loopback() {
        if !m.get_flag("allow-remote") {
            return Err(Failure::new(code::USAGE, s.msg_remote_refused));
        }
        eprintln!("{}", s.msg_remote_warning);
    }
    let hash = TokenHash::load(path).map_err(|e| Failure::from_error(&e, lang))?;
    let io_err = |e: std::io::Error| Failure::from_error(&e.into(), lang);
    // DE: Socket binden, solange `bind` noch erlaubt ist; danach Sandbox – vor dem Start
    //     der tokio-Threads, damit Landlock auch für sie gilt.
    // EN: Bind the socket while `bind` is still allowed; then the sandbox – before the
    //     tokio threads start, so that Landlock applies to them as well.
    let listener = std::net::TcpListener::bind(addr).map_err(io_err)?;
    listener.set_nonblocking(true).map_err(io_err)?;
    sandbox::enable(Profile::Api, sandboxed, m.get_flag("verbose"), lang)?;
    run(listener, hash, lang)
}

/// DE: Startet die Laufzeit und bedient Anfragen bis Strg+C.
/// EN: Starts the runtime and serves requests until Ctrl+C.
fn run(listener: std::net::TcpListener, hash: TokenHash, lang: Lang) -> CliResult {
    let s = serve_texts(lang);
    let io_err = |e: std::io::Error| Failure::from_error(&e.into(), lang);
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .map_err(io_err)?;
    runtime.block_on(async {
        let listener = tokio::net::TcpListener::from_std(listener).map_err(io_err)?;
        let local = listener.local_addr().map_err(io_err)?;
        eprintln!("{} http://{local}", s.msg_listening);
        let state = AppState::new(hash, Limits::default());
        let shutdown = async {
            let _ = tokio::signal::ctrl_c().await;
        };
        api::serve(listener, state, shutdown).await.map_err(io_err)
    })?;
    eprintln!("{}", s.msg_stopped);
    Ok(())
}
