package org.keycloak.social.wechat;

import org.jboss.logging.Logger;
import org.keycloak.broker.oidc.OAuth2IdentityProviderConfig;
import org.keycloak.models.IdentityProviderModel;

/**
 * @author shuaihu.zhang
 */
public class WechatWorkProviderConfig extends OAuth2IdentityProviderConfig {

  private static final Logger log = Logger.getLogger(WechatWorkProviderConfig.class);
  public WechatWorkProviderConfig(IdentityProviderModel model) {
    super(model);
  }

  public WechatWorkProviderConfig() {
    super();
  }

  public String getAgentId() {
    return getConfig().get("agentId");
  }

  public void setAgentId(String agentId) {
    getConfig().put("agentId", agentId);
  }

  public String getQrcodeAuthorizationUrl() {
    return getConfig().get("qrcodeAuthorizationUrl");
  }

  public void setQrcodeAuthorizationUrl(String qrcodeAuthorizationUrl) {
    getConfig().put("qrcodeAuthorizationUrl", qrcodeAuthorizationUrl);
  }

}
