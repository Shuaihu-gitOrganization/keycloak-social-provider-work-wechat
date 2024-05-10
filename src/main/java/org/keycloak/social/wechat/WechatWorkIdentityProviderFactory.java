//
// Source code recreated from a .class file by IntelliJ IDEA
// (powered by FernFlower decompiler)
//

package org.keycloak.social.wechat;

import org.jboss.logging.Logger;
import org.keycloak.broker.oidc.AbstractOAuth2IdentityProvider;
import org.keycloak.broker.provider.AbstractIdentityProviderFactory;
import org.keycloak.broker.social.SocialIdentityProviderFactory;
import org.keycloak.models.IdentityProviderModel;
import org.keycloak.models.KeycloakSession;

public class WechatWorkIdentityProviderFactory extends AbstractIdentityProviderFactory<WechatWorkIdentityProvider> implements SocialIdentityProviderFactory<WechatWorkIdentityProvider> {
    public static final String PROVIDER_ID = "wechat-work";
    protected static final Logger logger = Logger.getLogger(AbstractOAuth2IdentityProvider.class);

    public WechatWorkIdentityProviderFactory() {
    }

    @Override
    public String getName() {
        return "WechatWork";
    }

    @Override
    public WechatWorkIdentityProvider create(KeycloakSession session, IdentityProviderModel model) {
        logger.info("create ---- session ----- > " + session);
        return new WechatWorkIdentityProvider(session, new WechatWorkProviderConfig(model));
    }

    @Override
    public String getId() {
        return "wechat-work";
    }

    @Override
    public WechatWorkProviderConfig createConfig() {
        return new WechatWorkProviderConfig();
    }
}
