package org.keycloak.social.wechat;

import org.keycloak.broker.oidc.mappers.AbstractJsonUserAttributeMapper;
import org.keycloak.broker.provider.BrokeredIdentityContext;
import org.keycloak.models.IdentityProviderMapperModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;

/** User attribute mapper. */
public class WechatWorkUserAttributeMapper extends AbstractJsonUserAttributeMapper {
  private static final String PROFILE_MOBILE = WechatWorkIdentityProviderV2.PROFILE_MOBILE;
  private static final String PROFILE_GENDER = WechatWorkIdentityProviderV2.PROFILE_GENDER;
  private static final String PROFILE_STATUS = WechatWorkIdentityProviderV2.PROFILE_STATUS;
  private static final String PROFILE_ENABLE = WechatWorkIdentityProviderV2.PROFILE_ENABLE;
  private static final String[] cp = new String[] {WechatWorkIdentityProviderFactory.PROVIDER_ID};

  @Override
  public String[] getCompatibleProviders() {
    logger.info("wechat-work-user-attribute-mapper"+cp);
    return cp;
  }

  @Override
  public String getId() {
    return "wechat-work-user-attribute-mapper";
  }

  @Override
  public void updateBrokeredUser(
      KeycloakSession session,
      RealmModel realm,
      UserModel user,
      IdentityProviderMapperModel mapperModel,
      BrokeredIdentityContext context) {
    user.setSingleAttribute(PROFILE_MOBILE, context.getUserAttribute(PROFILE_MOBILE));
    user.setSingleAttribute(PROFILE_GENDER, context.getUserAttribute(PROFILE_GENDER));
    user.setSingleAttribute(PROFILE_STATUS, context.getUserAttribute(PROFILE_STATUS));
    user.setSingleAttribute(PROFILE_ENABLE, context.getUserAttribute(PROFILE_ENABLE));
  }
}
