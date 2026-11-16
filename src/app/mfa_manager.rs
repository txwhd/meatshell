use super::*;
use crate::totp::MfaProfile;

fn clear_form(window: &AppWindow) {
    window.set_mfa_selected_id("".into());
    window.set_mfa_entry_name("".into());
    window.set_mfa_secret_input("".into());
    window.set_mfa_algorithm("SHA1".into());
    window.set_mfa_digits("6".into());
    window.set_mfa_period("30".into());
    window.set_mfa_message("".into());
}

fn load_form(window: &AppWindow, profile: &MfaProfile) {
    window.set_mfa_selected_id(profile.id.clone().into());
    window.set_mfa_entry_name(profile.name.clone().into());
    window.set_mfa_secret_input("".into());
    window.set_mfa_algorithm(profile.algorithm.clone().into());
    window.set_mfa_digits(profile.digits.to_string().into());
    window.set_mfa_period(profile.period.to_string().into());
    window.set_mfa_message("".into());
}

pub(super) fn refresh(window: &AppWindow, store: &ConfigStore) {
    let now = crate::totp::now();
    let mut ids = vec![SharedString::from("")];
    let mut labels = vec![SharedString::from(t(
        "手动输入（不引用）",
        "Manual input (no reference)",
    ))];
    let rows = store
        .mfa_profiles()
        .iter()
        .map(|profile| {
            ids.push(profile.id.clone().into());
            labels.push(profile.name.clone().into());
            MfaEntryInfo {
                id: profile.id.clone().into(),
                name: profile.name.clone().into(),
                detail: format!(
                    "{} · {} / {}s",
                    profile.algorithm, profile.digits, profile.period
                )
                .into(),
                code: profile
                    .code_at(now)
                    .unwrap_or_else(|_| t("不可用", "Unavailable").into())
                    .into(),
                remaining: format!("{}s", profile.remaining_at(now)).into(),
            }
        })
        .collect::<Vec<_>>();
    window.set_mfa_entries(ModelRc::new(VecModel::from(rows)));
    if !window.get_mfa_ids().iter().eq(ids.iter().cloned())
        || !window.get_mfa_choices().iter().eq(labels.iter().cloned())
    {
        window.set_mfa_ids(ModelRc::new(VecModel::from(ids.clone())));
        window.set_mfa_choices(ModelRc::new(VecModel::from(labels)));
    }
    let reference = window.get_dialog_mfa_profile_id();
    let choice = ids.iter().position(|id| id == &reference).unwrap_or(0);
    if choice == 0 && !reference.is_empty() {
        window.set_dialog_mfa_profile_id("".into());
    }
    window.set_dialog_mfa_choice(choice as i32);
    let selected = window.get_mfa_selected_id();
    if !selected.is_empty() && store.mfa_profile(&selected).is_none() {
        clear_form(window);
    }
}

pub(super) fn wire(ctx: &WinCtx) {
    wire_controls(&ctx.window, ctx.store.clone(), ctx.registry.clone());
}

fn wire_controls(
    window: &AppWindow,
    shared_store: Rc<RefCell<ConfigStore>>,
    shared_registry: Rc<WindowRegistry<slint::Weak<AppWindow>>>,
) {
    let timer = Rc::new(slint::Timer::default());
    let weak = window.as_weak();
    let store = shared_store.clone();
    timer.start(
        slint::TimerMode::Repeated,
        std::time::Duration::from_secs(1),
        move || {
            if let Some(w) = weak.upgrade() {
                if w.get_mfa_manager_open() || w.get_mfa_prompt_open() || w.get_dialog_open() {
                    refresh(&w, &store.borrow());
                }
            }
        },
    );
    let weak = window.as_weak();
    let store = shared_store.clone();
    window.on_open_mfa_manager(move || {
        let _keep_timer = &timer;
        if let Some(w) = weak.upgrade() {
            refresh(&w, &store.borrow());
            w.set_mfa_manager_open(true);
        }
    });
    let weak = window.as_weak();
    let store = shared_store.clone();
    window.on_refresh_mfa(move || {
        if let Some(w) = weak.upgrade() {
            refresh(&w, &store.borrow());
        }
    });
    let weak = window.as_weak();
    window.on_mfa_new_entry(move || {
        if let Some(w) = weak.upgrade() {
            clear_form(&w);
        }
    });

    let weak = window.as_weak();
    let store = shared_store.clone();
    window.on_mfa_select_entry(move |id| {
        let store = store.borrow();
        if let (Some(w), Some(profile)) = (weak.upgrade(), store.mfa_profile(&id)) {
            w.set_mfa_selected_id(profile.id.clone().into());
            w.set_mfa_entry_name(profile.name.clone().into());
            w.set_mfa_secret_input("".into());
            w.set_mfa_algorithm(profile.algorithm.clone().into());
            w.set_mfa_digits(profile.digits.to_string().into());
            w.set_mfa_period(profile.period.to_string().into());
            w.set_mfa_message("".into());
        }
    });
    let weak = window.as_weak();
    let store = shared_store.clone();
    let registry = shared_registry.clone();
    window.on_mfa_save_entry(move || {
        let Some(w) = weak.upgrade() else {
            return;
        };
        let result: Result<String> = (|| {
            let mut store = store.borrow_mut();
            let selected = w.get_mfa_selected_id();
            let existing = store.mfa_profile(&selected).cloned();
            if !selected.is_empty() && existing.is_none() {
                anyhow::bail!("MFA 条目已删除 / MFA entry was deleted");
            }
            let id = existing
                .as_ref()
                .map(|profile| profile.id.clone())
                .unwrap_or_else(|| uuid::Uuid::new_v4().to_string());
            let input = if w.get_mfa_secret_input().trim().is_empty() {
                existing
                    .as_ref()
                    .map(|profile| profile.secret.clone())
                    .unwrap_or_default()
            } else {
                Secret::new(w.get_mfa_secret_input().to_string())
            };
            let digits = w
                .get_mfa_digits()
                .parse()
                .map_err(|_| anyhow::anyhow!("验证码位数无效 / invalid digits"))?;
            let period = w
                .get_mfa_period()
                .parse()
                .map_err(|_| anyhow::anyhow!("验证码周期无效 / invalid period"))?;
            let profile = MfaProfile::from_input(
                id.clone(),
                &w.get_mfa_entry_name(),
                input.as_str(),
                &w.get_mfa_algorithm(),
                digits,
                period,
            )?;
            store.put_mfa_profile(profile)?;
            Ok(id)
        })();
        match result {
            Ok(id) => {
                if let Some(profile) = store.borrow().mfa_profile(&id) {
                    load_form(&w, profile);
                }
                refresh(&w, &store.borrow());
                w.set_mfa_message(t("已加密保存", "Saved with local encryption").into());
                registry.broadcast_config_changed();
            }
            Err(error) => w.set_mfa_message(error.to_string().into()),
        }
    });
    let weak = window.as_weak();
    let store = shared_store.clone();
    let registry = shared_registry.clone();
    window.on_mfa_delete_entry(move || {
        let Some(w) = weak.upgrade() else {
            return;
        };
        let result = store
            .borrow_mut()
            .delete_mfa_profile(&w.get_mfa_selected_id());
        match result {
            Ok(()) => {
                clear_form(&w);
                refresh(&w, &store.borrow());
                registry.broadcast_config_changed();
            }
            Err(error) => w.set_mfa_message(error.to_string().into()),
        }
    });
    let weak = window.as_weak();
    let store = shared_store.clone();
    window.on_mfa_copy_code(move |id| {
        let result: Result<()> = (|| {
            let store = store.borrow();
            let profile = store
                .mfa_profile(&id)
                .context("MFA 条目不存在 / MFA entry not found")?;
            let code = profile.code_at(crate::totp::now())?;
            arboard::Clipboard::new()?.set_text(code)?;
            Ok(())
        })();
        if let Some(w) = weak.upgrade() {
            w.set_mfa_message(if result.is_ok() {
                t("动态码已复制", "Code copied").into()
            } else {
                t(
                    "无法复制动态码，请检查条目",
                    "Cannot copy code; check the entry",
                )
                .into()
            });
        }
    });
    let weak = window.as_weak();
    let store = shared_store.clone();
    window.on_mfa_fill_code(move || {
        let Some(w) = weak.upgrade() else {
            return;
        };
        let index = w.get_mfa_prompt_choice();
        let Some(id) = w.get_mfa_ids().row_data(index.max(0) as usize) else {
            return;
        };
        if let Some(profile) = store.borrow().mfa_profile(&id) {
            if let Ok(code) = profile.code_at(crate::totp::now()) {
                w.set_mfa_answer(code.into());
            }
        }
    });
    refresh(window, &shared_store.borrow());
}

#[cfg(test)]
mod tests {
    use super::*;
    use slint::platform::software_renderer::{MinimalSoftwareWindow, RepaintBufferType};
    struct Backend(Rc<MinimalSoftwareWindow>);
    impl slint::platform::Platform for Backend {
        fn create_window_adapter(
            &self,
        ) -> std::result::Result<Rc<dyn slint::platform::WindowAdapter>, slint::PlatformError>
        {
            Ok(self.0.clone())
        }
    }
    #[test]
    fn manage_reference_fill_and_delete_without_revealing_secret() {
        std::thread::spawn(|| {
            let adapter = MinimalSoftwareWindow::new(RepaintBufferType::NewBuffer);
            slint::platform::set_platform(Box::new(Backend(adapter.clone()))).unwrap();
            let window = AppWindow::new().unwrap();
            let path =
                std::env::temp_dir().join(format!("ms-mfa-ui-{}.json", uuid::Uuid::new_v4()));
            let store = Rc::new(RefCell::new(crate::config::fixture_store(
                path.clone(),
                Vec::new(),
            )));
            wire_controls(&window, store.clone(), Rc::new(WindowRegistry::default()));
            window.set_mfa_entry_name("RFC test account".into());
            window.set_mfa_secret_input("JBSWY3DPEHPK3PXP".into());
            window.invoke_mfa_save_entry();
            assert_eq!(store.borrow().mfa_profiles().len(), 1);
            let id = window.get_mfa_selected_id();
            assert!(!id.is_empty());
            assert!(window.get_mfa_secret_input().is_empty());
            assert!(!std::fs::read_to_string(&path)
                .unwrap()
                .contains("JBSWY3DPEHPK3PXP"));
            window.invoke_mfa_select_entry(id.clone());
            assert!(window.get_mfa_secret_input().is_empty());
            window.set_mfa_entry_name("RFC renamed".into());
            window.invoke_mfa_save_entry();
            assert_eq!(
                store.borrow().mfa_profile(&id).unwrap().secret.as_str(),
                "JBSWY3DPEHPK3PXP"
            );
            let mut session = Session::new_empty();
            session.mfa_profile_id = id.to_string();
            store.borrow_mut().upsert(session);
            store.borrow().save().unwrap();
            window.set_dialog_mfa_profile_id(id.clone());
            window.invoke_refresh_mfa();
            assert_eq!(window.get_dialog_mfa_choice(), 1);
            window.set_mfa_prompt_open(true);
            window.set_mfa_prompt_choice(1);
            window.invoke_mfa_fill_code();
            assert_eq!(window.get_mfa_answer().len(), 6);
            assert!(window.get_mfa_prompt_open());
            window.set_mfa_prompt_open(false);
            window.set_mfa_answer("".into());
            window.invoke_open_mfa_manager();
            window.show().unwrap();
            adapter.set_size(slint::PhysicalSize::new(1000, 760));
            let before = window.get_mfa_entries().row_data(0).unwrap().remaining;
            std::thread::sleep(std::time::Duration::from_millis(1100));
            slint::platform::update_timers_and_animations();
            assert_ne!(
                window.get_mfa_entries().row_data(0).unwrap().remaining,
                before
            );
            let mut pixels = vec![slint::Rgb8Pixel::default(); 1000 * 760];
            adapter.request_redraw();
            assert!(adapter.draw_if_needed(|renderer| {
                renderer.render(&mut pixels, 1000);
            }));
            if let Ok(output) = std::env::var("MEATSHELL_MFA_UI_IMAGE") {
                let raw = pixels
                    .into_iter()
                    .flat_map(|pixel| [pixel.r, pixel.g, pixel.b])
                    .collect();
                image::RgbImage::from_raw(1000, 760, raw)
                    .unwrap()
                    .save(output)
                    .unwrap();
            }
            window.invoke_mfa_delete_entry();
            assert!(store.borrow().mfa_profiles().is_empty());
            assert!(store.borrow().sessions()[0].mfa_profile_id.is_empty());
            assert!(window.get_dialog_mfa_profile_id().is_empty());
            assert!(window.get_mfa_secret_input().is_empty());
            let _ = std::fs::remove_file(path);
        })
        .join()
        .unwrap();
    }
}
