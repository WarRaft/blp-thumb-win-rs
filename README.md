# BLP Thumbnail & Preview Handler

- Меню инсталлятора теперь содержит единый пункт `Install (all users)` и `Uninstall (all users)` — регистрация выполняется сразу в HKLM и HKCU.
- DLL экспортирует два COM-класса: обработчик миниатюр и обработчик превью для проводника Windows.
- Утилита автоматически обновляет `ShellEx`, `PreviewHandlers`, ключи `Approved` и сбрасывает кэш для обоих CLSID.
- Пункт меню `Enable/Disable log` включает подробный лог только по запросу (по умолчанию сбор отключён) и при отключении удаляет файл `blp-thumb-win.log` с рабочего стола.
- Для отката выберите `Uninstall (all users)` и затем `Restart Explorer`, чтобы обновить проводник.
- Дополнительно см. документацию по shell handlers: https://learn.microsoft.com/en-us/windows/win32/shell/handlers
