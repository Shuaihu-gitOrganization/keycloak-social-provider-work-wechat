//
// Source code recreated from a .class file by IntelliJ IDEA
// (powered by FernFlower decompiler)
//

package org.keycloak.social.wechat;

import org.keycloak.broker.oidc.OAuth2IdentityProviderConfig;
import org.keycloak.models.IdentityProviderModel;

public class WechatWorkProviderConfig extends OAuth2IdentityProviderConfig {
  private static final long serialVersionUID = 1L;

  public WechatWorkProviderConfig(IdentityProviderModel model) {
    super(model);
  }

  public WechatWorkProviderConfig() {
  }

  public String getAgentId() {
    return (String)this.getConfig().get("agentId");
  }

  public void setAgentId(String agentId) {
    this.getConfig().put("agentId", agentId);
  }

  public String getQrcodeAuthorizationUrl() {
    return (String)this.getConfig().get("qrcodeAuthorizationUrl");
  }

  public void setQrcodeAuthorizationUrl(String qrcodeAuthorizationUrl) {
    this.getConfig().put("qrcodeAuthorizationUrl", qrcodeAuthorizationUrl);
  }
}
