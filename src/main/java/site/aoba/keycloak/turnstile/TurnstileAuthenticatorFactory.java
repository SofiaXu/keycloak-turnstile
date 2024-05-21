package site.aoba.keycloak.turnstile;

import java.util.List;

import org.keycloak.Config.Scope;
import org.keycloak.authentication.Authenticator;
import org.keycloak.authentication.AuthenticatorFactory;
import org.keycloak.models.AuthenticationExecutionModel;
import org.keycloak.models.AuthenticationExecutionModel.Requirement;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.models.credential.PasswordCredentialModel;
import org.keycloak.provider.ProviderConfigProperty;
import org.keycloak.provider.ProviderConfigurationBuilder;

public class TurnstileAuthenticatorFactory implements AuthenticatorFactory {
    public static final String PROVIDER_ID = "cf-turnstile";
    public static final TurnstileAuthenticator SINGLETON = new TurnstileAuthenticator();
    public static final AuthenticationExecutionModel.Requirement[] REQUIREMENT_CHOICES = {
            AuthenticationExecutionModel.Requirement.REQUIRED
    };

    @Override
    public void close() {
    }

    @Override
    public Authenticator create(KeycloakSession arg0) {
        return SINGLETON;
    }

    @Override
    public String getId() {
        return PROVIDER_ID;
    }

    @Override
    public void init(Scope arg0) {
    }

    @Override
    public void postInit(KeycloakSessionFactory arg0) {
    }

    @Override
    public String getDisplayType() {
        return "Cloudflare Turnstile";
    }

    @Override
    public String getReferenceCategory() {
        return PasswordCredentialModel.TYPE;
    }

    @Override
    public Requirement[] getRequirementChoices() {
        return REQUIREMENT_CHOICES;
    }

    @Override
    public boolean isConfigurable() {
        return true;
    }

    @Override
    public boolean isUserSetupAllowed() {
        return false;
    }

    @Override
    public List<ProviderConfigProperty> getConfigProperties() {
        return ProviderConfigurationBuilder.create()
                .property()
                .name(TurnstileAuthenticator.TURNSTILE_SITE_KEY)
                .label("Site Key")
                .type(ProviderConfigProperty.STRING_TYPE)
                .helpText("The site key of the Turnstile service.")
                .add()
                .property()
                .name(TurnstileAuthenticator.TURNSTILE_SECRET_KEY)
                .label("Secret Key")
                .type(ProviderConfigProperty.STRING_TYPE)
                .helpText("The secret key of the Turnstile service.")
                .add().build();
    }

    @Override
    public String getHelpText() {
        return "Cloudflare Turnstile authenticator";
    }

}
