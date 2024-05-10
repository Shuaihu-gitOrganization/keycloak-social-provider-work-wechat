//
// Source code recreated from a .class file by IntelliJ IDEA
// (powered by FernFlower decompiler)
//

package org.keycloak.social.wechat;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.google.common.cache.Cache;
import com.google.common.cache.CacheBuilder;
import java.net.URI;
import java.util.Iterator;
import java.util.concurrent.TimeUnit;


import jakarta.ws.rs.GET;
import jakarta.ws.rs.QueryParam;
import jakarta.ws.rs.WebApplicationException;
import jakarta.ws.rs.core.*;
import org.keycloak.broker.oidc.AbstractOAuth2IdentityProvider;
import org.keycloak.broker.oidc.mappers.AbstractJsonUserAttributeMapper;
import org.keycloak.broker.provider.AuthenticationRequest;
import org.keycloak.broker.provider.BrokeredIdentityContext;
import org.keycloak.broker.provider.IdentityBrokerException;
import org.keycloak.broker.provider.IdentityProvider;
import org.keycloak.broker.provider.util.SimpleHttp;
import org.keycloak.broker.social.SocialIdentityProvider;
import org.keycloak.common.ClientConnection;
import org.keycloak.events.EventBuilder;
import org.keycloak.events.EventType;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.services.ErrorPage;
import org.keycloak.sessions.AuthenticationSessionModel;

public class WechatWorkIdentityProvider extends AbstractOAuth2IdentityProvider<WechatWorkProviderConfig> implements SocialIdentityProvider<WechatWorkProviderConfig> {
  public static final String AUTH_URL = "https://open.weixin.qq.com/connect/oauth2/authorize";
  public static final String QRCODE_AUTH_URL = "https://open.work.weixin.qq.com/wwopen/sso/qrConnect";
  public static final String TOKEN_URL = "https://qyapi.weixin.qq.com/cgi-bin/gettoken";
  public static final String DEFAULT_SCOPE = "snsapi_base";
  public static final String DEFAULT_RESPONSE_TYPE = "code";
  public static final String WEIXIN_REDIRECT_FRAGMENT = "wechat_redirect";
  public static final String PROFILE_URL = "https://qyapi.weixin.qq.com/cgi-bin/user/getuserinfo";
  public static final String PROFILE_DETAIL_URL = "https://qyapi.weixin.qq.com/cgi-bin/user/get";
  public static final String PROFILE_DEPARTMENT_URL = "https://qyapi.weixin.qq.com/cgi-bin/department/list";
  public static final String OAUTH2_PARAMETER_CLIENT_ID = "appid";
  public static final String OAUTH2_PARAMETER_AGENT_ID = "agentid";
  public static final String OAUTH2_PARAMETER_RESPONSE_TYPE = "response_type";
  public static final String WEIXIN_CORP_ID = "corpid";
  public static final String WEIXIN_CORP_SECRET = "corpsecret";
  public static final String PROFILE_MOBILE = "mobile";
  public static final String PROFILE_GENDER = "gender";
  public static final String PROFILE_STATUS = "status";
  public static final String PROFILE_ENABLE = "enable";
  public static final String PROFILE_USERID = "userid";
  public static final String PROFILE_NAME = "name";
  public static final String PROFILE_EMAIL = "email";
  public static final String PROFILE_POSITION = "position";
  public static final String PROFILE_AVATAR = "avatar";
  public static final String PROFILE_THUMB_AVATAR = "thumb_avatar";
  public static final String PROFILE_ISLEADER = "isleader";
  public static final String PROFILE_ENGLISH_NAME = "english_name";
  public static final String PROFILE_TELEPHONE = "telephone";
  public static final String PROFILE_MAIN_DEPARTMENT = "main_department";
  public static final String PROFILE_MAIN_DEPARTMENT_NAME = "main_department_name";
  public static final String PROFILE_DEPARTMENT = "department";
  public static final String PROFILE_DEPARTMENT_NAME = "department_name";
  public static final String PROFILE_QR_CODE = "qr_code";
  public static final String PROFILE_ALIAS = "alias";
  public static final String PROFILE_ADDRESS = "address";
  public static final String PROFILE_IDP_TYPE = "idp_type";
  public static final String IDP_TYPE = "wechat-work";
  public static final String ATTRIBUTE_PREFIX = "wechat_work_";
  private String ACCESS_TOKEN_KEY = "access_token";
  private String ACCESS_TOKEN_CACHE_KEY = "wechat_work_sso_access_token";
  public static String WECHAT_WORK_CACHE_NAME = "wechat_work_sso";
  public static Cache<String, String> sso_cache;

  private String get_access_token() {
    try {
      String token = (String)sso_cache.getIfPresent(this.ACCESS_TOKEN_CACHE_KEY + ((WechatWorkProviderConfig)this.getConfig()).getClientId() + ((WechatWorkProviderConfig)this.getConfig()).getAgentId());
      if (token == null) {
        JsonNode j = this._renew_access_token();
        if (j == null) {
          j = this._renew_access_token();
          if (j == null) {
            throw new Exception("renew access token error");
          }

          logger.debug("retry in renew access token " + j.toString());
        }

        token = this.getJsonProperty(j, this.ACCESS_TOKEN_KEY);
        sso_cache.put(this.ACCESS_TOKEN_CACHE_KEY + ((WechatWorkProviderConfig)this.getConfig()).getClientId() + ((WechatWorkProviderConfig)this.getConfig()).getAgentId(), token);
      }

      return token;
    } catch (Exception var3) {
      logger.error(var3);
      var3.printStackTrace(System.out);
      return null;
    }
  }

  private JsonNode _renew_access_token() {
    try {
      logger.info("doGet ----- > " + this.session);
      JsonNode j = SimpleHttp.doGet("https://qyapi.weixin.qq.com/cgi-bin/gettoken", this.session).param("corpid", ((WechatWorkProviderConfig)this.getConfig()).getClientId()).param("corpsecret", ((WechatWorkProviderConfig)this.getConfig()).getClientSecret()).asJson();
      logger.info("request wechat work access token " + j.toString());
      return j;
    } catch (Exception var2) {
      logger.error(var2);
      var2.printStackTrace(System.out);
      return null;
    }
  }

  private String reset_access_token() {
    sso_cache.invalidate(this.ACCESS_TOKEN_CACHE_KEY + ((WechatWorkProviderConfig)this.getConfig()).getClientId() + ((WechatWorkProviderConfig)this.getConfig()).getAgentId());
    return this.get_access_token();
  }

  public WechatWorkIdentityProvider(KeycloakSession session, WechatWorkProviderConfig config) {
    super(session, config);
    logger.info("WechatWorkIdentityProvider ---- session ----- > " + session);
    config.setAuthorizationUrl("https://open.weixin.qq.com/connect/oauth2/authorize");
    config.setQrcodeAuthorizationUrl("https://open.work.weixin.qq.com/wwopen/sso/qrConnect");
    config.setAgentId("1000003");
    new Endpoint(session);
    config.setTokenUrl("https://qyapi.weixin.qq.com/cgi-bin/gettoken");
    config.setDefaultScope("snsapi_base");
  }

  @Override
  public Object callback(RealmModel realm, IdentityProvider.AuthenticationCallback callback, EventBuilder event) {
    return new Endpoint(callback, realm, event, this.session);
  }

  @Override
  protected boolean supportsExternalExchange() {
    return true;
  }

  private String removeflag(String str) {
    if (str == null) {
      return null;
    } else {
      while(str.startsWith(",")) {
        str = str.substring(1);
      }

      while(str.endsWith(",")) {
        str = str.substring(0, str.length() - 1);
      }

      return str;
    }
  }

  @Override
  protected BrokeredIdentityContext extractIdentityFromProfile(EventBuilder event, JsonNode profile) {
    String userid = this.getJsonProperty(profile, "userid");
    String email = this.getJsonProperty(profile, "email");
    String mobile = this.getJsonProperty(profile, "mobile");
    String name = this.getJsonProperty(profile, "name");
    BrokeredIdentityContext identity = new BrokeredIdentityContext(userid);
    identity.setUsername(userid);
    identity.setBrokerUserId(userid);
    identity.setModelUsername(userid);
    identity.setEmail(email);
    identity.setFirstName(name != null ? name : userid);
    identity.setLastName(mobile == null ? "wechat-work" : mobile);
    identity.setUserAttribute("idp_type", "wechat-work");
    identity.setUserAttribute("userid", userid);
    identity.setUserAttribute("name", name);
    identity.setUserAttribute("mobile", mobile);
    identity.setUserAttribute("gender", this.getJsonProperty(profile, "gender"));
    identity.setUserAttribute("status", this.getJsonProperty(profile, "status"));
    identity.setUserAttribute("enable", this.getJsonProperty(profile, "enable"));
    identity.setUserAttribute("position", this.getJsonProperty(profile, "position"));
    identity.setUserAttribute("avatar", this.getJsonProperty(profile, "avatar"));
    identity.setUserAttribute("thumb_avatar", this.getJsonProperty(profile, "thumb_avatar"));
    identity.setUserAttribute("isleader", this.getJsonProperty(profile, "isleader"));
    identity.setUserAttribute("english_name", this.getJsonProperty(profile, "english_name"));
    identity.setUserAttribute("telephone", this.getJsonProperty(profile, "telephone"));
    identity.setUserAttribute("main_department", this.getJsonProperty(profile, "main_department"));
    identity.setUserAttribute("main_department_name", this.getJsonProperty(profile, "main_department_name"));
    identity.setUserAttribute("department", this.removeflag(this.getJsonProperty(profile, "department")));
    identity.setUserAttribute("department_name", this.removeflag(this.getJsonProperty(profile, "department_name")));
    identity.setUserAttribute("qr_code", this.getJsonProperty(profile, "qr_code"));
    identity.setUserAttribute("alias", this.getJsonProperty(profile, "alias"));
    identity.setUserAttribute("address", this.getJsonProperty(profile, "address"));
    identity.setUserAttribute("wechat_work_userid", this.getJsonProperty(profile, "userid"));
    identity.setUserAttribute("wechat_work_name", this.getJsonProperty(profile, "name"));
    identity.setUserAttribute("wechat_work_position", this.getJsonProperty(profile, "position"));
    identity.setUserAttribute("wechat_work_department_name", this.removeflag(this.getJsonProperty(profile, "department_name")));
    identity.setUserAttribute("wechat_work_main_department_name", this.getJsonProperty(profile, "main_department_name"));
    identity.setIdpConfig(this.getConfig());
    identity.setIdp(this);
    AbstractJsonUserAttributeMapper.storeUserProfileForMapper(identity, profile, ((WechatWorkProviderConfig)this.getConfig()).getAlias());
    return identity;
  }

  @Override
  public BrokeredIdentityContext getFederatedIdentity(String authorizationCode) {
    String accessToken = this.get_access_token();
    if (accessToken == null) {
      throw new IdentityBrokerException("No access token available");
    } else {
      BrokeredIdentityContext context = null;

      try {
        JsonNode profile = SimpleHttp.doGet("https://qyapi.weixin.qq.com/cgi-bin/user/getuserinfo", this.session).param(this.ACCESS_TOKEN_KEY, accessToken).param("code", authorizationCode).asJson();
        logger.info("profile first " + profile.toString());
        long errcode = (long)profile.get("errcode").asInt();
        if (errcode == 42001L || errcode == 40014L) {
          accessToken = this.reset_access_token();
          profile = SimpleHttp.doGet("https://qyapi.weixin.qq.com/cgi-bin/user/getuserinfo", this.session).param(this.ACCESS_TOKEN_KEY, accessToken).param("code", authorizationCode).asJson();
          logger.info("profile retried " + profile.toString());
        }

        if (errcode != 0L) {
          throw new IdentityBrokerException("get user info failed, please retry");
        }

        profile = SimpleHttp.doGet("https://qyapi.weixin.qq.com/cgi-bin/user/get", this.session).param(this.ACCESS_TOKEN_KEY, accessToken).param("userid", this.getJsonProperty(profile, "UserId")).asJson();
        logger.info("get userInfo =" + profile.toPrettyString());
        JsonNode departmen = SimpleHttp.doGet("https://qyapi.weixin.qq.com/cgi-bin/department/list", this.session).param(this.ACCESS_TOKEN_KEY, accessToken).param("id", this.getJsonProperty(profile, "main_department")).asJson();
        logger.info("get dept =" + profile.toPrettyString());
        ObjectNode profileNode = (ObjectNode)profile;
        profileNode.put("main_department_name", "");
        JsonNode departmenArray = departmen.get("department");
        if (departmen.has("department") && !departmenArray.isNull() && departmenArray.isArray()) {
          Iterator var10 = departmenArray.iterator();

          while(var10.hasNext()) {
            JsonNode objNode = (JsonNode)var10.next();
            if (profile.get("main_department").asInt() == objNode.get("id").asInt()) {
              profileNode.put("main_department_name", this.getJsonProperty(objNode, "name"));
              break;
            }
          }
        }

        if (profile.has("department") && !profile.get("department").isNull() && profile.get("department").isArray()) {
          JsonNode departmentIdArray = profile.get("department");
          if (departmentIdArray.size() == 1) {
            profileNode.put("department", this.getJsonProperty(profileNode, "main_department"));
            profileNode.put("department_name", this.getJsonProperty(profileNode, "main_department_name"));
          } else {
            profileNode.put("department", ",");
            profileNode.put("department_name", ",");
            Iterator var19 = departmentIdArray.iterator();

            label74:
            while(true) {
              while(true) {
                JsonNode departmentId;
                JsonNode departmenArray_item;
                do {
                  JsonNode departmen_item;
                  do {
                    do {
                      if (!var19.hasNext()) {
                        break label74;
                      }

                      departmentId = (JsonNode)var19.next();
                      departmen_item = SimpleHttp.doGet("https://qyapi.weixin.qq.com/cgi-bin/department/list", this.session).param(this.ACCESS_TOKEN_KEY, accessToken).param("id", departmentId.asText()).asJson();
                      departmenArray_item = departmen_item.get("department");
                    } while(!departmen_item.has("department"));
                  } while(departmenArray_item.isNull());
                } while(!departmenArray_item.isArray());

                Iterator var15 = departmenArray_item.iterator();

                while(var15.hasNext()) {
                  JsonNode item = (JsonNode)var15.next();
                  if (departmentId.asInt() == item.get("id").asInt()) {
                    profileNode.put("department", this.getJsonProperty(profileNode, "department") + departmentId.asText() + ",");
                    profileNode.put("department_name", this.getJsonProperty(profileNode, "department_name") + this.getJsonProperty(item, "name") + ",");
                    break;
                  }
                }
              }
            }
          }
        }

        logger.info("get department =" + profileNode.toPrettyString());
        context = this.extractIdentityFromProfile((EventBuilder)null, profileNode);
      } catch (Exception var17) {
        logger.error(var17);
        var17.printStackTrace(System.out);
      }

      context.getContextData().put("FEDERATED_ACCESS_TOKEN", accessToken);
      return context;
    }
  }

  @Override
  public Response performLogin(AuthenticationRequest request) {
    try {
      URI authorizationUrl = this.createAuthorizationUrl(request).build(new Object[0]);
      logger.info("auth url " + authorizationUrl.toString());
      return Response.seeOther(authorizationUrl).build();
    } catch (Exception var3) {
      var3.printStackTrace(System.out);
      throw new IdentityBrokerException("Could not create authentication request. ---- > ", var3);
    }
  }

  @Override
  protected String getDefaultScopes() {
    return "snsapi_base";
  }

  @Override
  protected UriBuilder createAuthorizationUrl(AuthenticationRequest request) {
    HttpHeaders headers = request.getHttpRequest().getHttpHeaders();
    String ua = headers.getHeaderString("User-Agent");
    logger.info("createAuthorizationUrl User-Agent =" + ua);
    UriBuilder uriBuilder;
    if (ua != null && ua.indexOf("wxwork") > 0) {
      logger.info("Start creating connection 1 ----- > {}" + ((WechatWorkProviderConfig)this.getConfig()).getAuthorizationUrl());
      uriBuilder = UriBuilder.fromUri(((WechatWorkProviderConfig)this.getConfig()).getAuthorizationUrl());
      logger.info("Connection creation complete 2 ----- > {}" + uriBuilder);
      uriBuilder.queryParam("appid", new Object[]{((WechatWorkProviderConfig)this.getConfig()).getClientId()}).queryParam("redirect_uri", new Object[]{request.getRedirectUri()}).queryParam("state", new Object[]{request.getState().getEncoded()}).queryParam("response_type", new Object[]{"code"}).queryParam("scope", new Object[]{"snsapi_base"});
      uriBuilder.fragment("wechat_redirect");
      logger.info("创建连接1 ----- 》 {}" + uriBuilder);
    } else {
      logger.info("Start creating connection 2 ----- > {}" + ((WechatWorkProviderConfig)this.getConfig()).getAuthorizationUrl());
      uriBuilder = UriBuilder.fromUri(((WechatWorkProviderConfig)this.getConfig()).getQrcodeAuthorizationUrl());
      logger.info("Connection creation complete 2 ----- > {}" + uriBuilder.toString());
      uriBuilder.queryParam("appid", new Object[]{((WechatWorkProviderConfig)this.getConfig()).getClientId()}).queryParam("agentid", new Object[]{((WechatWorkProviderConfig)this.getConfig()).getAgentId()}).queryParam("redirect_uri", new Object[]{request.getRedirectUri()}).queryParam("state", new Object[]{request.getState().getEncoded()});
      logger.info("创建连接2 ----- 》 {}" + uriBuilder);
    }

    return uriBuilder;
  }

  @Override
  public void updateBrokeredUser(KeycloakSession session, RealmModel realm, UserModel user, BrokeredIdentityContext context) {
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
    user.setSingleAttribute("telephone", context.getUserAttribute("telephone"));
    user.setSingleAttribute("main_department", context.getUserAttribute("main_department"));
    user.setSingleAttribute("main_department_name", context.getUserAttribute("main_department_name"));
    user.setSingleAttribute("department", context.getUserAttribute("department"));
    user.setSingleAttribute("department_name", context.getUserAttribute("department_name"));
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

  static {
    sso_cache = CacheBuilder.newBuilder().maximumSize(10000000L).expireAfterWrite(1L, TimeUnit.HOURS).build();
  }

  protected class Endpoint {
    protected IdentityProvider.AuthenticationCallback callback;
    protected RealmModel realm;
    protected EventBuilder event;
    @Context
    protected KeycloakSession session;
    @Context
    protected ClientConnection clientConnection;
    @Context
    protected HttpHeaders headers;
    @Context
    protected UriInfo uriInfo;

    public Endpoint(IdentityProvider.AuthenticationCallback callback, RealmModel realm, EventBuilder event, KeycloakSession session) {
      WechatWorkIdentityProvider.logger.info("Endpoint ---- session ---- > " + session);
      this.callback = callback;
      this.realm = realm;
      this.event = event;
      this.session = session;
    }

    public Endpoint(KeycloakSession session) {
      this.session = session;
    }

    @GET
    public Response authResponse(@QueryParam("state") String state, @QueryParam("code") String authorizationCode, @QueryParam("error") String error, @QueryParam("appid") String client_id) {
      WechatWorkIdentityProvider.logger.info("state ---- " + state);
      WechatWorkIdentityProvider.logger.info("appid ---- " + client_id);
      WechatWorkIdentityProvider.logger.info("ERROR ---- " + error);
      WechatWorkIdentityProvider.logger.info("OAUTH2_PARAMETER_CODE=" + authorizationCode);
      if (error != null) {
        WechatWorkIdentityProvider.logger.error(error + " for broker login " + ((WechatWorkProviderConfig)WechatWorkIdentityProvider.this.getConfig()).getProviderId());
        if (error.equals("access_denied")) {
          return this.callback.cancelled(WechatWorkIdentityProvider.this.getConfig());
        } else {
          return !error.equals("login_required") && !error.equals("interaction_required") ? this.callback.error("identityProviderUnexpectedErrorMessage") : this.callback.error(error);
        }
      } else {
        try {
          if (authorizationCode != null) {
            BrokeredIdentityContext federatedIdentity = WechatWorkIdentityProvider.this.getFederatedIdentity(authorizationCode);
            federatedIdentity.setIdpConfig(WechatWorkIdentityProvider.this.getConfig());
            federatedIdentity.setIdp(WechatWorkIdentityProvider.this);
            AuthenticationSessionModel authSession = this.callback.getAndVerifyAuthenticationSession(state);
            this.session.getContext().setAuthenticationSession(authSession);
            federatedIdentity.setAuthenticationSession(authSession);
            WechatWorkIdentityProvider.logger.info("authResponse success" + federatedIdentity);
            return this.callback.authenticated(federatedIdentity);
          }
        } catch (WebApplicationException var7) {
          var7.printStackTrace(System.out);
          return var7.getResponse();
        } catch (Exception var8) {
          WechatWorkIdentityProvider.logger.error("Failed to make identity provider oauth callback", var8);
          var8.printStackTrace(System.out);
        }

        this.event.event(EventType.LOGIN);
        this.event.error("identity_provider_login_failure");
        return ErrorPage.error(this.session, (AuthenticationSessionModel)null, Response.Status.BAD_GATEWAY, "identityProviderUnexpectedErrorMessage", new Object[0]);
      }
    }
  }
}
