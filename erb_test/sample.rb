if Account.current.msp?
  security_desk_url = "https://#{@portal_url}/admin/security"
end
if !Account.current.msp?
    I18n.t('mailer_notifier.security_notification.footer.user_instruction_new')
end
