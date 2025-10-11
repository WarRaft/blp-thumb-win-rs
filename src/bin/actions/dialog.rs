use crate::actiions::clear_cache::clear_cache;
use crate::actiions::install::install;
use crate::actiions::restart_explorer::restart_explorer;
use crate::actiions::toggle_logging::toggle_logging;
use crate::actiions::uninstall::uninstall;
use blp_thumb_win::log::log_enabled;
use dialoguer::Select;
use dialoguer::console::{Term, style};
use dialoguer::theme::ColorfulTheme;
use std::io;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Action {
    Install,
    Uninstall,
    RestartExplorer,
    ClearThumbCache,
    ToggleLogging,
    Exit,
}

fn theme() -> ColorfulTheme {
    // Force ASCII arrow; allow override via env MENU_ARROW if you ever need it.
    let mut t = ColorfulTheme::default();
    t.active_item_prefix = style(">".to_string());
    t.inactive_item_prefix = style(" ".to_string());
    t.picked_item_prefix = style(">".to_string());
    t.unpicked_item_prefix = style(" ".to_string());
    t.prompt_prefix = style("$".to_string());
    t.success_prefix = style(">".to_string());
    t.error_prefix = style("!".to_string());
    t
}

pub fn action_choose() -> io::Result<(Action, String)> {
    let mut actions = vec![Action::Install, Action::Uninstall, Action::RestartExplorer, Action::ClearThumbCache];

    let mut labels: Vec<String> = vec!["Install (current user)".into(), "Uninstall (current user)".into(), "Restart Explorer".into(), "Clear thumbnail cache".into()];

    let logging_enabled = log_enabled();
    actions.push(Action::ToggleLogging);
    labels.push(if logging_enabled { "Disable log" } else { "Enable log" }.into());

    actions.push(Action::Exit);
    labels.push("Exit".into());

    let label_refs: Vec<&str> = labels.iter().map(|s| s.as_str()).collect();

    let idx = Select::with_theme(&theme())
        .with_prompt("BLP Thumbnail Provider installer")
        .items(&label_refs)
        .default(0)
        .interact_on(&Term::stdout())?;

    Ok((actions[idx], labels[idx].clone()))
}

pub fn action_execute(action: Action) -> io::Result<()> {
    match action {
        Action::Install => install(),
        Action::Uninstall => uninstall(),
        Action::RestartExplorer => restart_explorer(),
        Action::ClearThumbCache => clear_cache(),
        Action::ToggleLogging => toggle_logging(),
        Action::Exit => Ok(()),
    }
}
