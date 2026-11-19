#![cfg_attr(all(windows, not(test)), windows_subsystem = "windows")]
//! Trusted per-user native adapter. Receives counts only, never source URLs,
//! credentials, release titles, user-provided paths or executable instructions.
//! Alerts are registered under the compiled-in `omd_notifications::identity`.
use std::io::Read;
fn main() {
    let mut bytes = Vec::new();
    let input = std::io::stdin().take(4097).read_to_end(&mut bytes).is_ok();
    let message = if input && bytes.len() <= 4096 {
        serde_json::from_slice::<omd_notifications::Message>(&bytes).ok()
    } else {
        None
    };
    let result = message
        .filter(|m| m.test || m.count > 0)
        .ok_or(())
        .and_then(show);
    if result.is_ok() {
        println!("{{\"accepted\":true}}");
    } else {
        println!("{}",serde_json::to_string(&omd_domain::Problem{code:"notification_unavailable".into(),message:"The operating system did not accept the notification. Enable OMD notifications in system settings and confirm that your desktop session is available.".into(),retryable:true,actions:vec!["retry_notification".into(),"open_inbox".into()]}).expect("problem JSON"));
        std::process::exit(1);
    }
}
fn show(message: omd_notifications::Message) -> Result<(), ()> {
    #[cfg(target_os = "macos")]
    notify_rust::set_application(omd_notifications::identity::APPLICATION).map_err(|_| ())?;
    let body = if message.test {
        "Desktop notifications are working. Subscription details remain in your OMD inbox."
            .to_owned()
    } else {
        format!(
            "{} new {} available. Open OMD to review your subscriptions.",
            message.count,
            if message.count == 1 {
                "release is"
            } else {
                "releases are"
            }
        )
    };
    let mut notification = notify_rust::Notification::new();
    notification
        .appname("OMD")
        .summary(if message.test {
            "OMD notification test"
        } else {
            "New subscription releases"
        })
        .body(&body);
    #[cfg(target_os = "windows")]
    notification.app_id(omd_notifications::identity::APPLICATION);
    #[cfg(all(unix, not(target_os = "macos")))]
    notification.hint(notify_rust::Hint::DesktopEntry(
        omd_notifications::identity::APPLICATION.into(),
    ));
    notification.show().map(|_| ()).map_err(|_| ())
}
