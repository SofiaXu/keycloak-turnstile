package site.aoba.keycloak.turnstile;

import java.net.HttpURLConnection;
import java.net.URL;

import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.AuthenticationFlowError;
import org.keycloak.authentication.authenticators.browser.UsernamePasswordForm;
import org.keycloak.events.Details;
import org.keycloak.forms.login.LoginFormsProvider;
import org.keycloak.models.AuthenticatorConfigModel;
import org.keycloak.models.utils.FormMessage;
import org.keycloak.services.ServicesLogger;
import org.keycloak.services.messages.Messages;
import org.keycloak.services.validation.Validation;

import jakarta.ws.rs.core.Response;

public class TurnstileAuthenticator extends UsernamePasswordForm {

    private static final ServicesLogger logger = ServicesLogger.LOGGER;
    public static final String PROVIDER_ID = "cf-turnstile";
    public static final String TURNSTILE_SITE_KEY = "cf-turnstile-site-key";
    public static final String TURNSTILE_SECRET_KEY = "cf-turnstile-secret-key";
    private String siteKey;
    private String userLanguageTag;

    @Override
    public void action(AuthenticationFlowContext context) {
        if (logger.isDebugEnabled()) {
            logger.debug("action(AuthenticationFlowContext) - start");
        }
        context.getEvent().detail(Details.AUTH_METHOD, "auth_method");
        String turnstileResponse = context.getHttpRequest().getDecodedFormParameters()
                .getFirst("cf-turnstile-response");
        if ((!Validation.isBlank(turnstileResponse)) && verifyTurnstile(turnstileResponse)) {
            super.action(context);
        } else {
            Response challenge = context.form().setError(Messages.RECAPTCHA_FAILED)
                    .createForm("login.ftl");
            context.failureChallenge(AuthenticationFlowError.INVALID_CREDENTIALS, challenge);
        }
        if (logger.isDebugEnabled()) {
            logger.debug("action(AuthenticationFlowContext) - end");
        }
    }

    @Override
    protected Response createLoginForm(LoginFormsProvider form) {
        form.setAttribute("turnstileRequired", true);
        form.setAttribute("turnstileSiteKey", siteKey);
        form.setAttribute("turnstileLang", userLanguageTag);
        form.addScript("https://challenges.cloudflare.com/turnstile/v0/api.js");
        return super.createLoginForm(form);
    }

    @Override
    public void authenticate(AuthenticationFlowContext context) {
        context.getEvent().detail(Details.AUTH_METHOD, "auth_method");
        if (logger.isInfoEnabled()) {
            logger.info(
                    "validateTurnstile(AuthenticationFlowContext, boolean, String, String) - Before the validation");
        }

        AuthenticatorConfigModel captchaConfig = context.getAuthenticatorConfig();
        LoginFormsProvider form = context.form();
        userLanguageTag = context.getSession().getContext().resolveLocale(context.getUser()).toLanguageTag();

        if (captchaConfig == null || captchaConfig.getConfig() == null
                || captchaConfig.getConfig().get(TURNSTILE_SITE_KEY) == null
                || captchaConfig.getConfig().get(TURNSTILE_SECRET_KEY) == null) {
            form.addError(new FormMessage(null, Messages.RECAPTCHA_NOT_CONFIGURED));
            return;
        }
        siteKey = captchaConfig.getConfig().get(TURNSTILE_SITE_KEY);
        form.setAttribute("turnstileRequired", true);
        form.setAttribute("turnstileSiteKey", siteKey);
        form.setAttribute("turnstileLang", userLanguageTag);
        form.addScript("https://challenges.cloudflare.com/turnstile/v0/api.js");

        super.authenticate(context);
    }

    private boolean verifyTurnstile(String turnstileResponse) {
        try {
            URL url = new URL("https://challenges.cloudflare.com/turnstile/v0/siteverify");
            HttpURLConnection connection = (HttpURLConnection) url.openConnection();
            connection.setRequestMethod("POST");
            connection.setRequestProperty("Content-Type", "application/x-www-form-urlencoded");
            connection.setDoOutput(true);
            connection.getOutputStream().write(("secret=" + "&response=" + turnstileResponse).getBytes());
            connection.connect();
            int responseCode = connection.getResponseCode();
            return responseCode == 200;
        } catch (Exception e) {
            logger.error("Failed to verify turnstile response", e);
            return false;
        }
    }

}
