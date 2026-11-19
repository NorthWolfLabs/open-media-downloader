#![cfg_attr(all(windows, not(test)), windows_subsystem = "windows")]
//! Engine-launched native sign-in window. See the library documentation for the
//! protocol. The page gets no bridge into OMD: no IPC handler, devtools,
//! downloads or non-web schemes, and the web view's data store is temporary.
use omd_credentials::{Cookie, SameSite, Session};
use omd_domain::HostGrant;
use omd_signin::{
    MAX_REQUEST, NativeCookie, Outcome, Request, STORAGE_SCRIPT, completed, credential_cookies,
    navigation_allowed, page_storage, popup_target,
};
use std::io::{Read, Write};
use std::time::{Duration, Instant};
use tao::{
    dpi::LogicalSize,
    event::{Event, WindowEvent},
    event_loop::{ControlFlow, EventLoopBuilder},
    window::WindowBuilder,
};
use wry::{NewWindowResponse, WebView, WebViewBuilder};

enum Message {
    Tick,
    Popup(String),
    Storage(String),
}
/// After the completion cookies appear, give the site a moment to finish its
/// own post-login writes (for example, page storage) before capturing.
const SETTLE: Duration = Duration::from_secs(3);
/// Capture even if the page never returns to a credential-authorized origin.
const SETTLE_LIMIT: Duration = Duration::from_secs(15);
const STORAGE_REPLY_LIMIT: Duration = Duration::from_secs(5);

fn emit(outcome: &Outcome) -> ! {
    let line = zeroize::Zeroizing::new(serde_json::to_string(outcome).expect("outcome serializes"));
    let mut out = std::io::stdout().lock();
    let _ = out.write_all(line.as_bytes());
    let _ = out.write_all(b"\n");
    let _ = out.flush();
    std::process::exit(match outcome {
        Outcome::Completed { .. } => 0,
        Outcome::Failed { .. } => 2,
        _ => 1,
    });
}
fn failed(code: &str) -> ! {
    emit(&Outcome::Failed { code: code.into() })
}
fn read_cookies(webview: &WebView, grants: &[HostGrant]) -> Vec<Cookie> {
    let native = webview
        .cookies()
        .unwrap_or_default()
        .into_iter()
        .map(|c| NativeCookie {
            name: c.name().into(),
            value: c.value().into(),
            domain: c.domain().unwrap_or_default().into(),
            path: c.path().map(Into::into),
            expires_at: c.expires_datetime().map(|t| t.unix_timestamp()),
            secure: c.secure(),
            http_only: c.http_only(),
            same_site: c.same_site().map(|s| match s {
                wry::cookie::SameSite::Strict => SameSite::Strict,
                wry::cookie::SameSite::Lax => SameSite::Lax,
                wry::cookie::SameSite::None => SameSite::None,
            }),
        })
        .collect();
    credential_cookies(native, grants, chrono::Utc::now().timestamp())
}
fn on_authorized_origin(webview: &WebView, grants: &[HostGrant]) -> bool {
    webview
        .url()
        .ok()
        .and_then(|u| url::Url::parse(&u).ok())
        .is_some_and(|u| {
            omd_credentials::origin_authorized(&u.origin().ascii_serialization(), grants)
        })
}

fn main() {
    let mut bytes = zeroize::Zeroizing::new(Vec::new());
    if std::io::stdin()
        .take(MAX_REQUEST as u64 + 1)
        .read_to_end(&mut bytes)
        .is_err()
    {
        failed("invalid_request");
    }
    let request = Request::parse(&bytes).unwrap_or_else(|code| failed(code));
    drop(bytes);
    #[cfg(target_os = "linux")]
    if std::env::var_os("DISPLAY").is_none() && std::env::var_os("WAYLAND_DISPLAY").is_none() {
        failed("display_unavailable");
    }
    // GTK initialization panics when no display can be opened.
    let built = std::panic::catch_unwind(|| EventLoopBuilder::<Message>::with_user_event().build());
    #[allow(unused_mut)]
    let mut event_loop = built.unwrap_or_else(|_| failed("display_unavailable"));
    #[cfg(target_os = "macos")]
    {
        use tao::platform::macos::{ActivationPolicy, EventLoopExtMacOS};
        event_loop.set_activation_policy(ActivationPolicy::Regular);
    }
    let window = WindowBuilder::new()
        .with_title(request.title.trim())
        .with_inner_size(LogicalSize::new(1000.0, 760.0))
        .with_focused(true)
        .build(&event_loop)
        .unwrap_or_else(|_| failed("display_unavailable"));
    let proxy = event_loop.create_proxy();
    let popups = proxy.clone();
    #[cfg(windows)]
    let mut context = wry::WebContext::new(Some(request.data_directory.clone()));
    #[cfg(windows)]
    let builder = WebViewBuilder::new_with_web_context(&mut context);
    #[cfg(not(windows))]
    let builder = WebViewBuilder::new();
    let builder = builder
        .with_url(&request.url)
        .with_incognito(true)
        .with_devtools(false)
        .with_navigation_handler(|url| navigation_allowed(&url))
        .with_new_window_req_handler(move |url, _| {
            if let Some(target) = popup_target(&url) {
                let _ = popups.send_event(Message::Popup(target));
            }
            NewWindowResponse::Deny
        })
        .with_download_started_handler(|_, _| false);
    #[cfg(not(target_os = "linux"))]
    let webview = builder
        .build(&window)
        .unwrap_or_else(|_| failed("webview_unavailable"));
    #[cfg(target_os = "linux")]
    let webview = {
        use tao::platform::unix::WindowExtUnix;
        use wry::WebViewBuilderExtUnix;
        let vbox = window
            .default_vbox()
            .unwrap_or_else(|| failed("webview_unavailable"));
        builder
            .build_gtk(vbox)
            .unwrap_or_else(|_| failed("webview_unavailable"))
    };
    window.set_focus();
    let ticker = proxy.clone();
    std::thread::spawn(move || {
        while ticker.send_event(Message::Tick).is_ok() {
            std::thread::sleep(Duration::from_millis(500));
        }
    });

    let deadline = Instant::now() + Duration::from_secs(request.timeout_seconds);
    let Request {
        grants,
        completion_cookies,
        ..
    } = request;
    let mut detected: Option<Instant> = None;
    let mut capture: Option<Instant> = None;
    event_loop.run(move |event, _, flow| {
        *flow = ControlFlow::Wait;
        let start_capture = |capture: &mut Option<Instant>| {
            if capture.is_some() {
                return;
            }
            *capture = Some(Instant::now());
            let reply = proxy.clone();
            if webview
                .evaluate_script_with_callback(STORAGE_SCRIPT, move |result| {
                    let _ = reply.send_event(Message::Storage(result));
                })
                .is_err()
            {
                finish(&webview, None, &grants, &completion_cookies);
            }
        };
        match event {
            Event::UserEvent(Message::Tick) => {
                if let Some(started) = capture {
                    if started.elapsed() > STORAGE_REPLY_LIMIT {
                        finish(&webview, None, &grants, &completion_cookies);
                    }
                    return;
                }
                if Instant::now() > deadline {
                    emit(&Outcome::Expired);
                }
                // With no declared completion cookies, the person finishes by
                // closing the window once signed in.
                let cookies = read_cookies(&webview, &grants);
                if !completion_cookies.is_empty() && completed(&cookies, &completion_cookies) {
                    let first = *detected.get_or_insert_with(Instant::now);
                    let settled =
                        first.elapsed() >= SETTLE && on_authorized_origin(&webview, &grants);
                    if settled || first.elapsed() >= SETTLE_LIMIT {
                        start_capture(&mut capture);
                    }
                } else {
                    detected = None;
                }
            }
            Event::UserEvent(Message::Popup(url)) => {
                let _ = webview.load_url(&url);
            }
            Event::UserEvent(Message::Storage(result)) => {
                if capture.is_some() {
                    finish(&webview, Some(result), &grants, &completion_cookies);
                }
            }
            Event::WindowEvent {
                event: WindowEvent::CloseRequested,
                ..
            } => {
                if completed(&read_cookies(&webview, &grants), &completion_cookies) {
                    start_capture(&mut capture);
                } else {
                    emit(&Outcome::Closed);
                }
            }
            _ => {}
        }
    });
}
fn finish(
    webview: &WebView,
    storage: Option<String>,
    grants: &[HostGrant],
    completion: &[String],
) -> ! {
    let cookies = read_cookies(webview, grants);
    if !completed(&cookies, completion) {
        emit(&Outcome::Closed);
    }
    let url = webview.url().unwrap_or_default();
    let storage = storage.map(zeroize::Zeroizing::new);
    let origins: Vec<_> = storage
        .and_then(|s| page_storage(&s, &url, grants))
        .into_iter()
        .collect();
    let mut session = Session {
        expires_at: None,
        cookies,
        headers: vec![],
        origins,
    };
    if session.validate(grants).is_err() {
        session.origins.clear();
    }
    emit(&Outcome::Completed { session })
}
