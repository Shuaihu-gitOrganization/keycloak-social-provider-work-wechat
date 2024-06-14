//
// Source code recreated from a .class file by IntelliJ IDEA
// (powered by FernFlower decompiler)
//

package org.keycloak.social.wechat;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.google.common.cache.Cache;
import com.google.common.cache.CacheBuilder;
import jakarta.ws.rs.GET;
import jakarta.ws.rs.QueryParam;
import jakarta.ws.rs.WebApplicationException;
import jakarta.ws.rs.core.HttpHeaders;
import jakarta.ws.rs.core.Response;
import jakarta.ws.rs.core.UriBuilder;
import org.keycloak.OAuth2Constants;
import org.keycloak.OAuthErrorException;
import org.keycloak.broker.oidc.AbstractOAuth2IdentityProvider;
import org.keycloak.broker.oidc.OAuth2IdentityProviderConfig;
import org.keycloak.broker.oidc.mappers.AbstractJsonUserAttributeMapper;
import org.keycloak.broker.provider.AuthenticationRequest;
import org.keycloak.broker.provider.BrokeredIdentityContext;
import org.keycloak.broker.provider.IdentityBrokerException;
import org.keycloak.broker.provider.IdentityProvider;
import org.keycloak.broker.provider.util.IdentityBrokerState;
import org.keycloak.broker.provider.util.SimpleHttp;
import org.keycloak.broker.social.SocialIdentityProvider;
import org.keycloak.common.ClientConnection;
import org.keycloak.crypto.KeyType;
import org.keycloak.crypto.KeyUse;
import org.keycloak.crypto.KeyWrapper;
import org.keycloak.crypto.SignatureSignerContext;
import org.keycloak.events.Errors;
import org.keycloak.events.EventBuilder;
import org.keycloak.events.EventType;
import org.keycloak.http.HttpRequest;
import org.keycloak.jose.jwk.JWKBuilder;
import org.keycloak.jose.jwk.RSAPublicJWK;
import org.keycloak.jose.jws.JWSBuilder;
import org.keycloak.models.*;
import org.keycloak.services.ErrorPage;
import org.keycloak.services.Urls;
import org.keycloak.services.managers.ClientSessionCode;
import org.keycloak.services.messages.Messages;
import org.keycloak.sessions.AuthenticationSessionModel;
import org.keycloak.vault.VaultStringSecret;

import java.net.URI;
import java.security.cert.X509Certificate;
import java.util.Collections;
import java.util.Iterator;
import java.util.List;
import java.util.Optional;
import java.util.concurrent.TimeUnit;

/**
 * @author shuaihu.zhang
 */
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
    private static final String ACCESS_TOKEN_KEY = "access_token";
    private static final String ACCESS_TOKEN_CACHE_KEY = "wechat_work_sso_access_token";
    public static final String WECHAT_WORK_CACHE_NAME = "wechat_work_sso";
    public static Cache<String, String> sso_cache;
    public WechatWorkIdentityProvider(KeycloakSession session, WechatWorkProviderConfig config) {
        super(session, config);
        logger.info("WechatWorkIdentityProvider ---- session ----- > " + session);
        config.setAuthorizationUrl(AUTH_URL);
        config.setQrcodeAuthorizationUrl(QRCODE_AUTH_URL);
        config.setAgentId("1000005");
        config.setTokenUrl(TOKEN_URL);
        config.setDefaultScope(DEFAULT_SCOPE);
    }


    private String get_access_token() {
        try {
            String token = (String) sso_cache.getIfPresent(this.ACCESS_TOKEN_CACHE_KEY + ((WechatWorkProviderConfig) this.getConfig()).getClientId() + ((WechatWorkProviderConfig) this.getConfig()).getAgentId());
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
                sso_cache.put(this.ACCESS_TOKEN_CACHE_KEY + ((WechatWorkProviderConfig) this.getConfig()).getClientId() + ((WechatWorkProviderConfig) this.getConfig()).getAgentId(), token);
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
            JsonNode j = SimpleHttp.doGet(TOKEN_URL, this.session).param(WEIXIN_CORP_ID, this.getConfig().getClientId()).param(WEIXIN_CORP_SECRET, this.getConfig().getClientSecret()).asJson();
            logger.info("request wechat work access token " + j.toString());
            return j;
        } catch (Exception var2) {
            logger.error(var2);
            var2.printStackTrace(System.out);
            return null;
        }
    }

    private String reset_access_token() {
        sso_cache.invalidate(this.ACCESS_TOKEN_CACHE_KEY + this.getConfig().getClientId() + this.getConfig().getAgentId());
        return this.get_access_token();
    }




    @Override
    protected boolean supportsExternalExchange() {
        return true;
    }

    private String removeflag(String str) {
        if (str == null) {
            return null;
        } else {
            while (str.startsWith(",")) {
                str = str.substring(1);
            }

            while (str.endsWith(",")) {
                str = str.substring(0, str.length() - 1);
            }

            return str;
        }
    }

    @Override
    protected BrokeredIdentityContext extractIdentityFromProfile(EventBuilder event, JsonNode profile) {
        String userid = this.getJsonProperty(profile, "userid");
        String email = this.getJsonProperty(profile, "email");
        String mobile = this.getJsonProperty(profile, PROFILE_MOBILE);
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
        identity.setUserAttribute(PROFILE_MOBILE, mobile);
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
        AbstractJsonUserAttributeMapper.storeUserProfileForMapper(identity, profile, ((WechatWorkProviderConfig) this.getConfig()).getAlias());
        return identity;
    }

    @Override
    public BrokeredIdentityContext getFederatedIdentity(String authorizationCode) {
        logger.info("getFederatedIdentity authorizationCode " + authorizationCode);

        String accessToken = this.get_access_token();
        if (accessToken == null) {
            throw new IdentityBrokerException("No access token available");
        }
        else if (authorizationCode.contains("47001")){
            throw new IdentityBrokerException("No authorizationCode available");
        }
        else {
            BrokeredIdentityContext context = null;

            try {
                JsonNode profile = SimpleHttp.doGet(PROFILE_URL, this.session).param(this.ACCESS_TOKEN_KEY, accessToken).param(DEFAULT_RESPONSE_TYPE, authorizationCode).asJson();
                logger.info("profile first " + profile.toString());
                long errcode = (long) profile.get("errcode").asInt();
                if (errcode == 42001L || errcode == 40014L) {
                    accessToken = this.reset_access_token();
                    profile = SimpleHttp.doGet("https://qyapi.weixin.qq.com/cgi-bin/cgi-bin/auth/getuserinfo", this.session).param(this.ACCESS_TOKEN_KEY, accessToken).param(DEFAULT_RESPONSE_TYPE, authorizationCode).asJson();
                    logger.info("profile retried " + profile.toString());
                }

                if (errcode != 0L) {
                    throw new IdentityBrokerException("get user info failed, please retry");
                }

                profile = SimpleHttp.doGet(PROFILE_DETAIL_URL, this.session).param(this.ACCESS_TOKEN_KEY, accessToken).param("userid", this.getJsonProperty(profile, "UserId")).asJson();
                logger.info("get userInfo =" + profile.toPrettyString());
                JsonNode departmen = SimpleHttp.doGet(PROFILE_DEPARTMENT_URL, this.session).param(this.ACCESS_TOKEN_KEY, accessToken).param("id", this.getJsonProperty(profile, "main_department")).asJson();
                logger.info("get dept =" + profile.toPrettyString());
                ObjectNode profileNode = (ObjectNode) profile;
                profileNode.put("main_department_name", "");
                JsonNode departmenArray = departmen.get("department");
                if (departmen.has("department") && !departmenArray.isNull() && departmenArray.isArray()) {
                    Iterator var10 = departmenArray.iterator();

                    while (var10.hasNext()) {
                        JsonNode objNode = (JsonNode) var10.next();
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
                        Iterator nodeIterator = departmentIdArray.iterator();

                        label74:
                        while (true) {
                            while (true) {
                                JsonNode departmentId;
                                JsonNode departmenArrayItem;
                                do {
                                    JsonNode departmenItem;
                                    do {
                                        do {
                                            if (!nodeIterator.hasNext()) {
                                                break label74;
                                            }

                                            departmentId = (JsonNode) nodeIterator.next();
                                            departmenItem = SimpleHttp.doGet(PROFILE_DEPARTMENT_URL, this.session).param(this.ACCESS_TOKEN_KEY, accessToken).param("id", departmentId.asText()).asJson();
                                            departmenArrayItem = departmenItem.get("department");
                                        } while (!departmenItem.has("department"));
                                    } while (departmenArrayItem.isNull());
                                } while (!departmenArrayItem.isArray());

                                Iterator<JsonNode> iterator = departmenArrayItem.iterator();

                                while (iterator.hasNext()) {
                                    JsonNode item = (JsonNode) iterator.next();
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
                context = this.extractIdentityFromProfile((EventBuilder) null, profileNode);
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
            URI authorizationUrl = this.createAuthorizationUrl(request).build();
            logger.info("auth url " + authorizationUrl.toString());
            Response response = Response.seeOther(authorizationUrl).build();
            logger.info("response " + response.toString());
            logger.info("responseBody " + response.getStatusInfo());
            return response;
        } catch (Exception e) {
            e.printStackTrace(System.out);
            throw new IdentityBrokerException("Could not create authentication request. ---- > ", e);
        }
    }

    @Override
    protected String getDefaultScopes() {
        return DEFAULT_SCOPE;
    }

    @Override
    protected UriBuilder createAuthorizationUrl(AuthenticationRequest request) {
        HttpHeaders headers = request.getHttpRequest().getHttpHeaders();
        String ua = headers.getHeaderString("User-Agent");
        logger.info("createAuthorizationUrl User-Agent =" + ua);
        logger.info("createAuthorizationUrl AuthenticationRequest =" + request.getState());
        logger.info("createAuthorizationUrl AuthenticationRequest =" + request.getState().getEncoded());
        UriBuilder uriBuilder;
        if (ua != null && ua.indexOf("wxwork") > 0) {
            logger.info("Start creating connection 1 ----- > {}" + this.getConfig().getAuthorizationUrl());
            uriBuilder = UriBuilder.fromUri(this.getConfig().getAuthorizationUrl());
            logger.info("Connection creation complete 2 ----- > {}" + uriBuilder);
            uriBuilder.queryParam(OAUTH2_PARAMETER_CLIENT_ID, this.getConfig().getClientId()).queryParam("redirect_uri", request.getRedirectUri()).queryParam("state", request.getState().getEncoded()).queryParam(OAUTH2_PARAMETER_RESPONSE_TYPE, DEFAULT_RESPONSE_TYPE).queryParam("scope", DEFAULT_SCOPE);
            uriBuilder.fragment(WEIXIN_REDIRECT_FRAGMENT);
            logger.info("创建连接1 ----- 》 {}" + uriBuilder);
        } else {
            logger.info("Start creating connection 2 ----- > {}" + this.getConfig().getAuthorizationUrl());
            uriBuilder = UriBuilder.fromUri(this.getConfig().getQrcodeAuthorizationUrl());
            logger.info("Connection creation complete 2 ----- > {}" + uriBuilder.toString());
            uriBuilder.queryParam(OAUTH2_PARAMETER_CLIENT_ID, this.getConfig().getClientId()).queryParam(OAUTH2_PARAMETER_AGENT_ID, this.getConfig().getAgentId()).queryParam("redirect_uri", request.getRedirectUri()).queryParam("state", request.getState().getEncoded());
            logger.info("创建连接2 ----- 》 {}" + uriBuilder);
        }

        return uriBuilder;
    }

    @Override
    public void updateBrokeredUser(KeycloakSession session, RealmModel realm, UserModel user, BrokeredIdentityContext context) {
        user.setSingleAttribute("idp_type", context.getUserAttribute("idp_type"));
        user.setSingleAttribute("name", context.getUserAttribute("name"));
        user.setSingleAttribute("userid", context.getUserAttribute("userid"));
        user.setSingleAttribute(PROFILE_MOBILE, context.getUserAttribute(PROFILE_MOBILE));
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
    @Override
    public Object callback(RealmModel realm, IdentityProvider.AuthenticationCallback callback, EventBuilder event) {
        return new Endpoint(callback, realm, event, this,this.session);
    }

    protected static class Endpoint extends AbstractOAuth2IdentityProvider.Endpoint{
        protected  AuthenticationCallback callback;
        protected  RealmModel realm;
        protected  EventBuilder event;
        private  WechatWorkIdentityProvider provider;

        protected  KeycloakSession session;

        protected  ClientConnection clientConnection;

        protected  HttpHeaders headers;

        protected  HttpRequest httpRequest;

        public Endpoint(AuthenticationCallback callback, RealmModel realm, EventBuilder event, WechatWorkIdentityProvider provider, KeycloakSession session) {
            super(callback,realm,event,provider);
            this.callback = callback;
            this.realm = realm;
            this.event = event;
            this.provider = provider;
            this.session = session;
            this.clientConnection = session.getContext().getConnection();
            this.httpRequest = session.getContext().getHttpRequest();
            this.headers = session.getContext().getRequestHeaders();
        }



        @Override
        @GET
        public Response authResponse(@QueryParam(AbstractOAuth2IdentityProvider.OAUTH2_PARAMETER_STATE) String state,
                                     @QueryParam(AbstractOAuth2IdentityProvider.OAUTH2_PARAMETER_CODE) String authorizationCode,
                                     @QueryParam(OAuth2Constants.ERROR) String error) {
            logger.info("authResponse authorizationCode ----- > " + authorizationCode);
            logger.info("authResponse state ----- > " + state);
            logger.info("authResponse error----- > " + error);

            OAuth2IdentityProviderConfig providerConfig = this.provider.getConfig();

            if (state == null) {
                logErroneousRedirectUrlError("Redirection URL does not contain a state parameter", providerConfig);
                return errorIdentityProviderLogin(Messages.IDENTITY_PROVIDER_MISSING_STATE_ERROR);
            }

            try {
                AuthenticationSessionModel authSession = this.callback.getAndVerifyAuthenticationSession(state);
                this.session.getContext().setAuthenticationSession(authSession);

                if (error != null) {
                    logErroneousRedirectUrlError("Redirection URL contains an error", providerConfig);
                    if (error.equals(ACCESS_DENIED)) {
                        return this.callback.cancelled(providerConfig);
                    } else if (error.equals(OAuthErrorException.LOGIN_REQUIRED) || error.equals(OAuthErrorException.INTERACTION_REQUIRED)) {
                        return this.callback.error(error);
                    } else {
                        return this.callback.error(Messages.IDENTITY_PROVIDER_UNEXPECTED_ERROR);
                    }
                }

                if (authorizationCode == null) {
                    logErroneousRedirectUrlError("Redirection URL neither contains a code nor error parameter",
                            providerConfig);
                    return errorIdentityProviderLogin(Messages.IDENTITY_PROVIDER_MISSING_CODE_OR_ERROR_ERROR);
                }

                SimpleHttp simpleHttp = generateTokenRequest(authorizationCode);
                String response;
                try (SimpleHttp.Response simpleResponse = simpleHttp.asResponse()) {
                    int status = simpleResponse.getStatus();
                    boolean success = status >= 200 && status < 400;
                    response = simpleResponse.asString();

                    if (!success) {
                        logger.errorf("Unexpected response from token endpoint %s. status=%s, response=%s",
                                simpleHttp.getUrl(), status, response);
                        return errorIdentityProviderLogin(Messages.IDENTITY_PROVIDER_UNEXPECTED_ERROR);
                    }
                }

                BrokeredIdentityContext federatedIdentity = this.provider.getFederatedIdentity(authorizationCode);

                if (providerConfig.isStoreToken()) {
                    // make sure that token wasn't already set by getFederatedIdentity();
                    // want to be able to allow provider to set the token itself.
                    if (federatedIdentity.getToken() == null) {
                        federatedIdentity.setToken(response);
                    }
                }

                federatedIdentity.setIdpConfig(providerConfig);
                federatedIdentity.setIdp(this.provider);
                federatedIdentity.setAuthenticationSession(authSession);

                return this.callback.authenticated(federatedIdentity);
            } catch (WebApplicationException e) {
                return e.getResponse();
            } catch (IdentityBrokerException e) {
                if (e.getMessageCode() != null) {
                    return errorIdentityProviderLogin(e.getMessageCode());
                }
                logger.error("Failed to make identity provider oauth callback", e);
                return errorIdentityProviderLogin(Messages.IDENTITY_PROVIDER_UNEXPECTED_ERROR);
            } catch (Exception e) {
                logger.error("Failed to make identity provider oauth callback", e);
                return errorIdentityProviderLogin(Messages.IDENTITY_PROVIDER_UNEXPECTED_ERROR);
            }
        }

        private void logErroneousRedirectUrlError(String mainMessage, OAuth2IdentityProviderConfig providerConfig) {
            String providerId = providerConfig.getProviderId();
            String redirectionUrl = session.getContext().getUri().getRequestUri().toString();

            logger.errorf("%s. providerId=%s, redirectionUrl=%s", mainMessage, providerId, redirectionUrl);
        }

        private Response errorIdentityProviderLogin(String message) {
            event.event(EventType.IDENTITY_PROVIDER_LOGIN);
            event.error(Errors.IDENTITY_PROVIDER_LOGIN_FAILURE);
            return ErrorPage.error(session, null, Response.Status.BAD_GATEWAY, message);
        }

        @Override
        public SimpleHttp generateTokenRequest(String authorizationCode) {
            KeycloakContext context = this.session.getContext();
            OAuth2IdentityProviderConfig providerConfig = this.provider.getConfig();
            logger.info("generateTokenRequest authorizationCode ----- > " + authorizationCode);
            logger.info("generateTokenRequest clientId ----- > " + providerConfig.getClientId());
            logger.info("generateTokenRequest clientSecret ----- > " + providerConfig.getClientSecret());
            logger.info("generateTokenRequest redirectUri ----- > " + Urls.identityProviderAuthnResponse(context.getUri().getBaseUri(),
                    providerConfig.getAlias(), context.getRealm().getName()).toString());
            logger.info("generateTokenRequest grantType ----- > " + OAUTH2_GRANT_TYPE_AUTHORIZATION_CODE);
            logger.info("generateTokenRequest providerConfig.getTokenUrl() ----- > " + providerConfig.getTokenUrl());

            SimpleHttp tokenRequest = SimpleHttp.doGet(providerConfig.getTokenUrl(), session)
                    .param(WEIXIN_CORP_ID, providerConfig.getClientId())
                    .param(WEIXIN_CORP_SECRET, providerConfig.getClientSecret())
                    .param(OAUTH2_PARAMETER_CODE, authorizationCode)
                    .param(OAUTH2_PARAMETER_REDIRECT_URI, Urls.identityProviderAuthnResponse(context.getUri().getBaseUri(),
                            providerConfig.getAlias(), context.getRealm().getName()).toString())
                    .param(OAUTH2_PARAMETER_GRANT_TYPE, "OAUTH2_GRANT_TYPE_AUTHORIZATION_CODE");

            if (providerConfig.isPkceEnabled()) {

                // reconstruct the original code verifier that was used to generate the code challenge from the HttpRequest.
                String stateParam = session.getContext().getUri().getQueryParameters().getFirst(OAuth2Constants.STATE);
                if (stateParam == null) {
                    logger.warn("Cannot lookup PKCE code_verifier: state param is missing.");
                    return tokenRequest;
                }

                RealmModel realm = context.getRealm();
                IdentityBrokerState idpBrokerState = IdentityBrokerState.encoded(stateParam, realm);
                ClientModel client = realm.getClientByClientId(idpBrokerState.getClientId());

                AuthenticationSessionModel authSession = ClientSessionCode.getClientSession(
                        idpBrokerState.getEncoded(),
                        idpBrokerState.getTabId(),
                        session,
                        realm,
                        client,
                        event,
                        AuthenticationSessionModel.class);

                if (authSession == null) {
                    logger.warnf("Cannot lookup PKCE code_verifier: authSession not found. state=%s", stateParam);
                    return tokenRequest;
                }

                String brokerCodeChallenge = authSession.getClientNote("BROKER_CODE_CHALLENGE_PARAM");
                if (brokerCodeChallenge == null) {
                    logger.warnf("Cannot lookup PKCE code_verifier: brokerCodeChallenge not found. state=%s", stateParam);
                    return tokenRequest;
                }

                tokenRequest.param(OAuth2Constants.CODE_VERIFIER, brokerCodeChallenge);
            }

            return this.provider.authenticateTokenRequest(tokenRequest);
        }



    }
    @Override
    public SimpleHttp authenticateTokenRequest(final SimpleHttp tokenRequest) {

        if (getConfig().isJWTAuthentication()) {
            String sha1x509Thumbprint = null;
            SignatureSignerContext signer = getSignatureContext();
            if (getConfig().isJwtX509HeadersEnabled()) {
                KeyWrapper key = session.keys().getKey(session.getContext().getRealm(), signer.getKid(), KeyUse.SIG, signer.getAlgorithm());
                if (key != null
                        && key.getStatus().isEnabled()
                        && key.getPublicKey() != null
                        && key.getUse().equals(KeyUse.SIG)
                        && key.getType().equals(KeyType.RSA)) {
                    JWKBuilder builder = JWKBuilder.create().kid(key.getKid()).algorithm(key.getAlgorithmOrDefault());
                    List<X509Certificate> certificates = Optional.ofNullable(key.getCertificateChain())
                            .filter(certs -> !certs.isEmpty())
                            .orElseGet(() -> Collections.singletonList(key.getCertificate()));
                    RSAPublicJWK jwk = (RSAPublicJWK) builder.rsa(key.getPublicKey(), certificates, key.getUse());
                    sha1x509Thumbprint = jwk.getSha1x509Thumbprint();
                }
            }
            String jws = new JWSBuilder().type(OAuth2Constants.JWT).x5t(sha1x509Thumbprint).jsonContent(generateToken()).sign(signer);
            return tokenRequest
                    .param(OAuth2Constants.CLIENT_ASSERTION_TYPE, OAuth2Constants.CLIENT_ASSERTION_TYPE_JWT)
                    .param(OAuth2Constants.CLIENT_ASSERTION, jws)
                    .param(OAuth2Constants.CLIENT_ID, getConfig().getClientId());
        } else {
            try (VaultStringSecret vaultStringSecret = session.vault().getStringSecret(getConfig().getClientSecret())) {
                if (getConfig().isBasicAuthentication()) {
                    return tokenRequest.authBasic(getConfig().getClientId(), vaultStringSecret.get().orElse(getConfig().getClientSecret()));
                }
                return tokenRequest
                        .param(WEIXIN_CORP_ID, getConfig().getClientId())
                        .param(WEIXIN_CORP_SECRET, vaultStringSecret.get().orElse(getConfig().getClientSecret()));
            }
        }
    }
}
