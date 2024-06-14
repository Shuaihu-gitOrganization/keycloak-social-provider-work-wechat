/*
 * Copyright 2016 Red Hat, Inc. and/or its affiliates
 * and other contributors as indicated by the @author tags.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.keycloak.social.wechat;

import com.fasterxml.jackson.databind.JsonNode;
import jakarta.ws.rs.core.UriBuilder;
import org.infinispan.Cache;
import org.infinispan.configuration.cache.ConfigurationBuilder;
import org.infinispan.manager.DefaultCacheManager;
import org.jboss.logging.Logger;
import org.keycloak.broker.oidc.AbstractOAuth2IdentityProvider;
import org.keycloak.broker.oidc.mappers.AbstractJsonUserAttributeMapper;
import org.keycloak.broker.provider.AuthenticationRequest;
import org.keycloak.broker.provider.BrokeredIdentityContext;
import org.keycloak.broker.provider.IdentityBrokerException;
import org.keycloak.broker.provider.util.SimpleHttp;
import org.keycloak.broker.social.SocialIdentityProvider;
import org.keycloak.events.EventBuilder;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;

import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;
import java.util.concurrent.TimeUnit;

/**
 * @author shuaihu.zhang
 */
public class WechatWorkIdentityProviderV2
        extends AbstractOAuth2IdentityProvider<WechatWorkProviderConfig>
        implements SocialIdentityProvider<WechatWorkProviderConfig> {
    private static final Logger log = Logger.getLogger(WechatWorkIdentityProviderV2.class);
    /**
     * 身份验证url
     */
    public static final String AUTH_URL = "https://open.weixin.qq.com/connect/oauth2/authorize";
    /**
     * qrcode auth url
     */
    public static final String QRCODE_AUTH_URL = "https://open.work.weixin.qq.com/wwopen/sso/qrConnect"; // 企业微信外使用
    /**
     * 标记url
     */
    public static final String TOKEN_URL = "https://qyapi.weixin.qq.com/cgi-bin/gettoken";

    /**
     * 默认范围
     */
    public static final String DEFAULT_SCOPE = "snsapi_base";
    /**
     * 默认响应类型
     */
    public static final String DEFAULT_RESPONSE_TYPE = "code";
    /**
     * weixin定向片段
     */
    public static final String WEIXIN_REDIRECT_FRAGMENT = "wechat_redirect";

    /**
     * 概要文件url
     */
    public static final String PROFILE_URL = "https://qyapi.weixin.qq.com/cgi-bin/user/getuserinfo";
    /**
     * 详细文件链接
     */
    public static final String PROFILE_DETAIL_URL = "https://qyapi.weixin.qq.com/cgi-bin/user/get";

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

    private final String ACCESS_TOKEN_KEY = "access_token";
    private final String ACCESS_TOKEN_CACHE_KEY = "wechat_work_sso_access_token";

    private static final DefaultCacheManager cacheManager = new DefaultCacheManager();
    private static final String WECHAT_WORK_CACHE_NAME = "wechat_work_sso";

    public WechatWorkIdentityProviderV2(KeycloakSession session, WechatWorkProviderConfig config) {

        super(session, config);
        logger.info("WechatWorkIdentityProvider构造器");
        //内部类接收keycloak session
        config.setAuthorizationUrl(AUTH_URL);
        //微信应用id
        config.setAgentId("1000005");
        config.setQrcodeAuthorizationUrl(QRCODE_AUTH_URL);
        config.setTokenUrl(TOKEN_URL);
    }
    private static final ConcurrentMap<String, Cache<String, String>> caches =
            new ConcurrentHashMap<>();

    private static Cache<String, String> createCache(String suffix) {
        ConfigurationBuilder configurationBuilder = null;
        try {
            log.info("create cache");
            String cacheName = WECHAT_WORK_CACHE_NAME + ":" + suffix;
            configurationBuilder = new ConfigurationBuilder();
            cacheManager.defineConfiguration(cacheName, configurationBuilder.build());

            Cache<String, String> cache = cacheManager.getCache(cacheName);
            logger.info("创建cache完成，信息：" + cache);
            return cache;
        } catch (Exception e) {
            logger.info("创建cache错误，错误信息为：" + e);
            e.printStackTrace(System.out);
            throw e;
        }
    }

    private Cache<String, String> getCache() {
        logger.info("getCache 缓存信息为：" + caches);
        return caches.computeIfAbsent(
                getConfig().getClientId() + ":" + getConfig().getAgentId(),
                WechatWorkIdentityProviderV2::createCache);
    }

    private String getAccessToken() {
        try {

            String token = getCache().get(ACCESS_TOKEN_CACHE_KEY);
            logger.info("getAccessToken" + token);
            log.info("get access token from cache" + token);
            if (token == null) {
                JsonNode j = renewAccessToken();
                if (j == null) {
                    j = renewAccessToken();
                    if (j == null) {
                        throw new Exception("renew access token error");
                    }
                    logger.info("retry in renew access token " + j);
                }
                token = getJsonProperty(j, ACCESS_TOKEN_KEY);
                long timeout = Integer.parseInt(getJsonProperty(j, "expires_in"));
                getCache().put(ACCESS_TOKEN_CACHE_KEY, token, timeout, TimeUnit.SECONDS);
            }
            return token;
        } catch (Exception e) {
            logger.info(e);
            e.printStackTrace(System.out);
        }
        return null;
    }

    private JsonNode renewAccessToken() {
        try {
            log.info("renew access token");
            return SimpleHttp.doGet(TOKEN_URL, session)
                    .param(WEIXIN_CORP_ID, getConfig().getClientId().replaceAll("\\+", ""))
                    .param(WEIXIN_CORP_SECRET, getConfig().getClientSecret())
                    .asJson();
        } catch (Exception e) {
            log.info("renew access token error");
            e.printStackTrace(System.out);
        }
        return null;
    }

    private String resetAccessToken() {
        log.info("reset access token");
        getCache().remove(ACCESS_TOKEN_CACHE_KEY);
        return getAccessToken();
    }



//    @Override
//    public Object callback(RealmModel realm, AuthenticationCallback callback, EventBuilder event) {
//        logger.info("callback回调信息 RealmModel:" + realm + " AuthenticationCallback:" + callback + " EventBuilder:" + event);
//        return new Endpoint(session, callback, realm, event, this);
//    }

    @Override
    protected boolean supportsExternalExchange() {
        return true;
    }

    @Override
    protected BrokeredIdentityContext extractIdentityFromProfile(
            EventBuilder event, JsonNode profile) {
        logger.info("用户信息JsonNode：" + profile.toString());
        // profile: see https://work.weixin.qq.com/api/doc#90000/90135/90196
        BrokeredIdentityContext identity =
                new BrokeredIdentityContext((getJsonProperty(profile, "userid")));

        identity.setUsername(getJsonProperty(profile, "userid").toLowerCase());
        identity.setBrokerUserId(getJsonProperty(profile, "userid").toLowerCase());
        identity.setModelUsername(getJsonProperty(profile, "userid").toLowerCase());
        String email = getJsonProperty(profile, "biz_mail");
        if (email == null || email.length() == 0) {
            email = getJsonProperty(profile, "email");
        }
        identity.setFirstName(email.split("@")[0].toLowerCase());
        identity.setLastName(getJsonProperty(profile, "name"));
        identity.setEmail(email);
        // 手机号码，第三方仅通讯录应用可获取
        identity.setUserAttribute(PROFILE_MOBILE, getJsonProperty(profile, "mobile"));
        // 性别。0表示未定义，1表示男性，2表示女性
        identity.setUserAttribute(PROFILE_GENDER, getJsonProperty(profile, "gender"));
        // 激活状态: 1=已激活，2=已禁用，4=未激活。
        // 已激活代表已激活企业微信或已关注微工作台（原企业号）。未激活代表既未激活企业微信又未关注微工作台（原企业号）。
        identity.setUserAttribute(PROFILE_STATUS, getJsonProperty(profile, "status"));
        // 成员启用状态。1表示启用的成员，0表示被禁用。注意，服务商调用接口不会返回此字段
        identity.setUserAttribute(PROFILE_ENABLE, getJsonProperty(profile, "enable"));
        identity.setUserAttribute(PROFILE_USERID, getJsonProperty(profile, "userid"));

        identity.setIdpConfig(getConfig());
        identity.setIdp(this);
        AbstractJsonUserAttributeMapper.storeUserProfileForMapper(
                identity, profile, getConfig().getAlias());
        return identity;
    }

    /**
     * 得到联邦身份
     *
     * @param authorizationCode 授权代码
     * @return {@link BrokeredIdentityContext}
     */
    @Override
    public BrokeredIdentityContext getFederatedIdentity(String authorizationCode) {
        String accessToken = getAccessToken();
        logger.info("getFederatedIdentity 授权代码：" + authorizationCode);
        logger.info("accessToken获取:" + accessToken);
        if (authorizationCode.contains("errcode")){
            throw new IdentityBrokerException("No authorizationCode available");
        }
        if (accessToken == null) {
            throw new IdentityBrokerException("No access token available");
        }
        BrokeredIdentityContext context = null;
        try {
            JsonNode profile;
            profile =
                    SimpleHttp.doGet(PROFILE_URL, session)
                            .param(ACCESS_TOKEN_KEY, accessToken)
                            .param("code", authorizationCode)
                            .asJson();
            logger.info("profile first " + profile.toString());
            // {"UserId":"ZhongXun","DeviceId":"10000556333395ZN","errcode":0,"errmsg":"ok"}
            // 全局错误码 https://work.weixin.qq.com/api/doc/90001/90148/90455
            // 42001	access_token已过期
            // 40014	不合法的access_token
            logger.info("profile first " + profile.toString());
            long errorCode = profile.get("errcode").asInt();
            if (errorCode == 42001 || errorCode == 40014) {
                accessToken = resetAccessToken();
                profile =
                        SimpleHttp.doGet(PROFILE_URL, session)
                                .param(ACCESS_TOKEN_KEY, accessToken)
                                .param("code", authorizationCode)
                                .asJson();
                logger.info("profile retried " + profile.toString());
            }
            if (errorCode != 0) {
                logger.error("get user info failed, please retry");
                throw new IdentityBrokerException("get user info failed, please retry");
            }
            logger.info("profile second " + profile.toString());
            profile =
                    SimpleHttp.doGet(PROFILE_DETAIL_URL, session)
                            .param(ACCESS_TOKEN_KEY, accessToken)
                            .param("userid", getJsonProperty(profile, "UserId"))
                            .asJson();
            logger.info("get userInfo =" + profile.toString());
            context = extractIdentityFromProfile(null, profile);
            context.getContextData().put(FEDERATED_ACCESS_TOKEN, accessToken);
        } catch (Exception e) {
            logger.error("getFederatedIdentity报错信息:" + e.getMessage());
            e.printStackTrace(System.out);
        }
        return context;
    }

    @Override
    protected String getDefaultScopes() {
        return DEFAULT_SCOPE;
    }

    /**
     * 创建授权url
     *
     * @param request 请求
     * @return {@link UriBuilder}
     */
    @Override
    protected UriBuilder createAuthorizationUrl(AuthenticationRequest request) {

        final UriBuilder uriBuilder;

        String ua =
                request.getHttpRequest().getHttpHeaders().getHeaderString("user-agent").toLowerCase();
        log.info("createAuthorizationUrl---->userAgent信息  = " + ua);
        if (ua.contains("wxwork")) {
            uriBuilder = UriBuilder.fromUri(getConfig().getAuthorizationUrl());
            uriBuilder
                    .queryParam(OAUTH2_PARAMETER_CLIENT_ID, getConfig().getClientId().replaceAll("\\+", ""))
                    .queryParam(OAUTH2_PARAMETER_REDIRECT_URI, request.getRedirectUri())
                    .queryParam(OAUTH2_PARAMETER_RESPONSE_TYPE, DEFAULT_RESPONSE_TYPE)
                    .queryParam(OAUTH2_PARAMETER_SCOPE, getConfig().getDefaultScope())
                    .queryParam(OAUTH2_PARAMETER_STATE, request.getState().getEncoded());
            uriBuilder.fragment(WEIXIN_REDIRECT_FRAGMENT);
            log.info("createAuthorizationUrl---->微信企业微信授权url = " + uriBuilder.build().toString());
        } else {
            uriBuilder = UriBuilder.fromUri(getConfig().getQrcodeAuthorizationUrl());
            uriBuilder
                    .queryParam(OAUTH2_PARAMETER_CLIENT_ID, getConfig().getClientId().replaceAll("\\+", ""))
                    .queryParam(OAUTH2_PARAMETER_AGENT_ID, getConfig().getAgentId())
                    .queryParam(OAUTH2_PARAMETER_REDIRECT_URI, request.getRedirectUri())
                    .queryParam(OAUTH2_PARAMETER_STATE, request.getState().getEncoded());
            log.info("createAuthorizationUrl---->微信企业微信授权url = " + uriBuilder.build().toString());
        }
        return uriBuilder;
    }

//    protected static class Endpoint {
//        //        protected AuthenticationCallback callback;
////        protected RealmModel realm;
////        protected EventBuilder event;
////
////        @Context
////        protected KeycloakSession session;
////
////        @Context
////        protected ClientConnection clientConnection;
////
////        @Context
////        protected HttpHeaders headers;
////
////        @Context
////        protected UriInfo uriInfo;
//        protected RealmModel realm;
//        protected AuthenticationCallback callback;
//        protected EventBuilder event;
//        private WechatWorkIdentityProvider provider;
//        @Context
//        protected KeycloakSession session;
//        @Context
//        protected ClientConnection clientConnection;
//
//        @Context
//        protected HttpHeaders headers;
//        @Context
//        protected  HttpRequest httpRequest;
//
//        public Endpoint(KeycloakSession session, AuthenticationCallback callback, RealmModel realm, EventBuilder event, WechatWorkIdentityProvider provider) {
//
//            this.session = session;
//            this.realm = session.getContext().getRealm();
//            this.clientConnection = session.getContext().getConnection();
//            this.callback = callback;
//            this.event = event;
//            this.provider = provider;
//            this.headers = session.getContext().getRequestHeaders();
//            this.httpRequest = session.getContext().getHttpRequest();
//            log.info("Endpoint---->session = " + session.toString());
//            log.info("Endpoint---->realm = " + realm.toString());
//            log.info("Endpoint---->event = " + event.toString());
//            log.info("Endpoint---->provider = " + provider.toString());
//            log.info("Endpoint---->headers = " + headers.toString());
//            log.info("Endpoint---->clientConnection = " + clientConnection.toString());
//            log.info("Endpoint---->callback = " + callback.toString());
//            log.info("Endpoint---->httpRequest = " + httpRequest.toString());
//
//        }
//        @GET
//        public Response authResponse(@QueryParam(AbstractOAuth2IdentityProvider.OAUTH2_PARAMETER_STATE) String state,
//                                     @QueryParam(AbstractOAuth2IdentityProvider.OAUTH2_PARAMETER_CODE) String authorizationCode,
//                                     @QueryParam(OAuth2Constants.ERROR) String error,
//                                     @QueryParam("appid")String appid) {
//            OAuth2IdentityProviderConfig providerConfig = provider.getConfig();
//
//            if (state == null) {
//                logErroneousRedirectUrlError("Redirection URL does not contain a state parameter", providerConfig);
//                return errorIdentityProviderLogin(Messages.IDENTITY_PROVIDER_MISSING_STATE_ERROR);
//            }
//
//            try {
//                AuthenticationSessionModel authSession = this.callback.getAndVerifyAuthenticationSession(state);
//                session.getContext().setAuthenticationSession(authSession);
//
//                if (error != null) {
//                    logErroneousRedirectUrlError("Redirection URL contains an error", providerConfig);
//                    if (error.equals(ACCESS_DENIED)) {
//                        return callback.cancelled(providerConfig);
//                    } else if (error.equals(OAuthErrorException.LOGIN_REQUIRED) || error.equals(OAuthErrorException.INTERACTION_REQUIRED)) {
//                        return callback.error(error);
//                    } else {
//                        return callback.error(Messages.IDENTITY_PROVIDER_UNEXPECTED_ERROR);
//                    }
//                }
//
//                if (authorizationCode == null) {
//                    logErroneousRedirectUrlError("Redirection URL neither contains a code nor error parameter",
//                            providerConfig);
//                    return errorIdentityProviderLogin(Messages.IDENTITY_PROVIDER_MISSING_CODE_OR_ERROR_ERROR);
//                }
//
//                SimpleHttp simpleHttp = generateTokenRequest(authorizationCode);
//                String response;
//                try (SimpleHttp.Response simpleResponse = simpleHttp.asResponse()) {
//                    int status = simpleResponse.getStatus();
//                    boolean success = status >= 200 && status < 400;
//                    response = simpleResponse.asString();
//
//                    if (!success) {
//                        logger.errorf("Unexpected response from token endpoint %s. status=%s, response=%s",
//                                simpleHttp.getUrl(), status, response);
//                        return errorIdentityProviderLogin(Messages.IDENTITY_PROVIDER_UNEXPECTED_ERROR);
//                    }
//                }
//
//                BrokeredIdentityContext federatedIdentity = provider.getFederatedIdentity(response);
//
//                if (providerConfig.isStoreToken()) {
//                    // make sure that token wasn't already set by getFederatedIdentity();
//                    // want to be able to allow provider to set the token itself.
//                    if (federatedIdentity.getToken() == null) {
//                        federatedIdentity.setToken(response);
//                    }
//                }
//
//                federatedIdentity.setIdpConfig(providerConfig);
//                federatedIdentity.setIdp(provider);
//                federatedIdentity.setAuthenticationSession(authSession);
//
//                return callback.authenticated(federatedIdentity);
//            } catch (WebApplicationException e) {
//                return e.getResponse();
//            } catch (IdentityBrokerException e) {
//                if (e.getMessageCode() != null) {
//                    return errorIdentityProviderLogin(e.getMessageCode());
//                }
//                logger.error("Failed to make identity provider oauth callback", e);
//                return errorIdentityProviderLogin(Messages.IDENTITY_PROVIDER_UNEXPECTED_ERROR);
//            } catch (Exception e) {
//                logger.error("Failed to make identity provider oauth callback", e);
//                return errorIdentityProviderLogin(Messages.IDENTITY_PROVIDER_UNEXPECTED_ERROR);
//            }
//        }
//
//        private void logErroneousRedirectUrlError(String mainMessage, OAuth2IdentityProviderConfig providerConfig) {
//            String providerId = providerConfig.getProviderId();
//            String redirectionUrl = session.getContext().getUri().getRequestUri().toString();
//
//            logger.errorf("%s. providerId=%s, redirectionUrl=%s", mainMessage, providerId, redirectionUrl);
//        }
//
//        private Response errorIdentityProviderLogin(String message) {
//            event.event(EventType.IDENTITY_PROVIDER_LOGIN);
//            event.error(Errors.IDENTITY_PROVIDER_LOGIN_FAILURE);
//            return ErrorPage.error(session, null, Response.Status.BAD_GATEWAY, message);
//        }
//
//        public SimpleHttp generateTokenRequest(String authorizationCode) {
//            KeycloakContext context = session.getContext();
//            OAuth2IdentityProviderConfig providerConfig = provider.getConfig();
//            SimpleHttp tokenRequest = SimpleHttp.doPost(providerConfig.getTokenUrl(), session)
//                    .param(OAUTH2_PARAMETER_CODE, authorizationCode)
//                    .param(OAUTH2_PARAMETER_REDIRECT_URI, Urls.identityProviderAuthnResponse(context.getUri().getBaseUri(),
//                            providerConfig.getAlias(), context.getRealm().getName()).toString())
//                    .param(OAUTH2_PARAMETER_GRANT_TYPE, OAUTH2_GRANT_TYPE_AUTHORIZATION_CODE);
//
//            if (providerConfig.isPkceEnabled()) {
//
//                // reconstruct the original code verifier that was used to generate the code challenge from the HttpRequest.
//                String stateParam = session.getContext().getUri().getQueryParameters().getFirst(OAuth2Constants.STATE);
//                if (stateParam == null) {
//                    logger.warn("Cannot lookup PKCE code_verifier: state param is missing.");
//                    return tokenRequest;
//                }
//
//                RealmModel realm = context.getRealm();
//                IdentityBrokerState idpBrokerState = IdentityBrokerState.encoded(stateParam, realm);
//                ClientModel client = realm.getClientByClientId(idpBrokerState.getClientId());
//
//                AuthenticationSessionModel authSession = ClientSessionCode.getClientSession(
//                        idpBrokerState.getEncoded(),
//                        idpBrokerState.getTabId(),
//                        session,
//                        realm,
//                        client,
//                        event,
//                        AuthenticationSessionModel.class);
//
//                if (authSession == null) {
//                    logger.warnf("Cannot lookup PKCE code_verifier: authSession not found. state=%s", stateParam);
//                    return tokenRequest;
//                }
//
//                String brokerCodeChallenge = authSession.getClientNote("BROKER_CODE_CHALLENGE_PARAM");
//                if (brokerCodeChallenge == null) {
//                    logger.warnf("Cannot lookup PKCE code_verifier: brokerCodeChallenge not found. state=%s", stateParam);
//                    return tokenRequest;
//                }
//
//                tokenRequest.param(OAuth2Constants.CODE_VERIFIER, brokerCodeChallenge);
//            }
//
//            return provider.authenticateTokenRequest(tokenRequest);
//        }
//
//
////        @GET
////        public Response authResponse(
////                @QueryParam("state") String state,
////                @QueryParam("code") String code,
////                @QueryParam("appid") String appid
////        ) {
////            log.info("Endpoint---->authResponse---->session = " + session.toString());
////            OAuth2IdentityProviderConfig providerConfig = provider.getConfig();
////            System.out.println(providerConfig);
////            log.info("authResponse---->providerConfig = " + providerConfig.toString());
////            log.info("authResponse---->headers = " + headers.toString());
////            log.info("OAUTH2_PARAMETER_STATE=" + state);
////            log.info("client_id=" + appid);
////            log.info("OAUTH2_PARAMETER_CODE=" + code);
////
////            // 以下样版代码从 AbstractOAuth2IdentityProvider 里获取的。
////            if (state == null) {
////                return errorIdentityProviderLogin(Messages.IDENTITY_PROVIDER_MISSING_STATE_ERROR);
////            }
////            try {
////                AuthenticationSessionModel authSession =
////                        this.callback.getAndVerifyAuthenticationSession(state);
////                log.info("authResponse---->authSession = " + authSession.toString());
////                session.getContext().setAuthenticationSession(authSession);
////
////                if (code != null) {
////                    BrokeredIdentityContext federatedIdentity = provider.getFederatedIdentity(code);
////                    log.info("federatedIdentity");
////                    federatedIdentity.setIdpConfig(provider.getConfig());
////                    federatedIdentity.setIdp(provider);
////                    federatedIdentity.setAuthenticationSession(authSession);
////                    return callback.authenticated(federatedIdentity);
////                }
////            } catch (WebApplicationException e) {
////                logger.error("Failed to make identity provider oauth callback WebApplicationException", e);
////                e.printStackTrace(System.out);
////                return e.getResponse();
////            } catch (Exception e) {
////                logger.error("Failed to make identity provider oauth callback", e);
////                e.printStackTrace(System.out);
////            }
////            return errorIdentityProviderLogin(Messages.IDENTITY_PROVIDER_UNEXPECTED_ERROR);
////        }
//
//    }

    @Override
    public void updateBrokeredUser(
            KeycloakSession session, RealmModel realm, UserModel user, BrokeredIdentityContext context) {
        log.info("updateBrokeredUser更新用户信息");
        user.setSingleAttribute(PROFILE_MOBILE, context.getUserAttribute(PROFILE_MOBILE));
        user.setSingleAttribute(PROFILE_GENDER, context.getUserAttribute(PROFILE_GENDER));
        user.setSingleAttribute(PROFILE_STATUS, context.getUserAttribute(PROFILE_STATUS));
        user.setSingleAttribute(PROFILE_ENABLE, context.getUserAttribute(PROFILE_ENABLE));
        user.setSingleAttribute(PROFILE_USERID, context.getUserAttribute(PROFILE_USERID));

        user.setUsername(context.getUsername());
        user.setFirstName(context.getFirstName());
        user.setLastName(context.getLastName());
        user.setEmail(context.getEmail());
    }
}
