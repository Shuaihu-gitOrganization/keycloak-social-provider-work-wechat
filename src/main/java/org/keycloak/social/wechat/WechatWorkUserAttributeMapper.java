package org.keycloak.social.wechat;

import org.keycloak.broker.oidc.mappers.AbstractJsonUserAttributeMapper;
import org.keycloak.broker.provider.BrokeredIdentityContext;
import org.keycloak.models.IdentityProviderMapperModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;

public class WechatWorkUserAttributeMapper extends AbstractJsonUserAttributeMapper {
  private static final String[] cp = new String[]{"wechat-work"};

  public WechatWorkUserAttributeMapper() {
  }

  @Override
  public String[] getCompatibleProviders() {
    return cp;
  }

  @Override
  public String getId() {
    return "wechat-work-user-attribute-mapper";
  }

  @Override
  public void updateBrokeredUser(KeycloakSession session, RealmModel realm, UserModel user, IdentityProviderMapperModel mapperModel, BrokeredIdentityContext context) {
    user.setSingleAttribute("idp_type", context.getUserAttribute("idp_type"));
    user.setSingleAttribute("name", context.getUserAttribute("name"));
    user.setSingleAttribute("userid", context.getUserAttribute("userid"));
    user.setSingleAttribute("mobile", context.getUserAttribute("mobile"));
    user.setSingleAttribute("gender", context.getUserAttribute("gender"));
    user.setSingleAttribute("status", context.getUserAttribute("status"));
    user.setSingleAttribute("enable", context.getUserAttribute("enable"));
    user.setSingleAttribute("position", context.getUserAttribute("position"));
    user.setSingleAttribute("avatar", context.getUserAttribute("avatar"));
    user.setSingleAttribute("thumb_avatar", context.getUserAttribute("thumb_avatar"));
    user.setSingleAttribute("isleader", context.getUserAttribute("isleader"));
    user.setSingleAttribute("english_name", context.getUserAttribute("english_name"));
    user.setSingleAttribute("main_department", context.getUserAttribute("main_department"));
    user.setSingleAttribute("main_department_name", context.getUserAttribute("main_department_name"));
    user.setSingleAttribute("department", context.getUserAttribute("department"));
    user.setSingleAttribute("department_name", context.getUserAttribute("department_name"));
    user.setSingleAttribute("telephone", context.getUserAttribute("telephone"));
    user.setSingleAttribute("qr_code", context.getUserAttribute("qr_code"));
    user.setSingleAttribute("alias", context.getUserAttribute("alias"));
    user.setSingleAttribute("address", context.getUserAttribute("address"));
    user.setSingleAttribute("wechat_work_name", context.getUserAttribute("name"));
    user.setSingleAttribute("wechat_work_userid", context.getUserAttribute("userid"));
    user.setSingleAttribute("wechat_work_position", context.getUserAttribute("position"));
    user.setSingleAttribute("wechat_work_department_name", context.getUserAttribute("department_name"));
    user.setSingleAttribute("wechat_work_main_department_name", context.getUserAttribute("main_department_name"));
    user.setUsername(context.getUsername());
    user.setEmail(context.getEmail());
    user.setFirstName(context.getFirstName());
    user.setLastName(context.getLastName());
  }
}
