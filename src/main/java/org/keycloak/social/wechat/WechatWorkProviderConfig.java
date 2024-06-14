package org.keycloak.social.wechat;

import org.jboss.logging.Logger;
import org.keycloak.broker.oidc.AbstractOAuth2IdentityProvider;
import org.keycloak.broker.oidc.OAuth2IdentityProviderConfig;
import org.keycloak.broker.oidc.OIDCIdentityProviderConfig;
import org.keycloak.models.IdentityProviderModel;

/**
 * @author shuaihu.zhang
 */
public class WechatWorkProviderConfig extends OAuth2IdentityProviderConfig {

  private static final Logger log = Logger.getLogger(WechatWorkProviderConfig.class);
  public WechatWorkProviderConfig(IdentityProviderModel model) {
    super(model);
    log.info("WechatWorkProviderConfig"+model);
  }

  public WechatWorkProviderConfig() {
    super();
  }

  public String getAgentId() {
    log.info("getAgentId"+getConfig().get("agentId"));
    return getConfig().get("agentId");
  }

  public void setAgentId(String agentId) {
    log.info("setAgentId"+agentId);
    getConfig().put("agentId", agentId);
  }

  public String getQrcodeAuthorizationUrl() {
    log.info("getQrcodeAuthorizationUrl"+getConfig().get("qrcodeAuthorizationUrl"));
    return getConfig().get("qrcodeAuthorizationUrl");
  }

  public void setQrcodeAuthorizationUrl(String qrcodeAuthorizationUrl) {
    log.info("setQrcodeAuthorizationUrl"+qrcodeAuthorizationUrl);
    getConfig().put("qrcodeAuthorizationUrl", qrcodeAuthorizationUrl);
  }

}
