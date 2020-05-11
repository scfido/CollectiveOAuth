using System;
using Come.CollectiveOAuth.Cache;
using Come.CollectiveOAuth.Config;
using Come.CollectiveOAuth.Enums;
using Come.CollectiveOAuth.Models;
using Come.CollectiveOAuth.Utils;

namespace Come.CollectiveOAuth.Request
{
    public partial class DefaultAuthRequest : IAuthRequest
    {
        protected ClientConfig config;
        protected IAuthSource source;
        protected IAuthStateCache authStateCache { set; get; }

        public DefaultAuthRequest(ClientConfig config, IAuthSource source)
        {
            this.config = config;
            this.source = source;
            this.authStateCache = new DefaultAuthStateCache();
        }

        public DefaultAuthRequest(ClientConfig config, IAuthSource source, IAuthStateCache authStateCache)
        {
            this.config = config;
            this.source = source;
            this.authStateCache = authStateCache;
        }

        public virtual AuthResponse Refresh(AuthToken authToken)
        {
            throw new System.NotImplementedException();
        }

        public virtual AuthResponse revoke(AuthToken authToken)
        {
            throw new System.NotImplementedException();
        }


        /**
         * 获取access token
         *
         * @param authCallback 授权成功后的回调参数
         * @return token
         * @see AuthDefaultRequest#authorize()
         * @see AuthDefaultRequest#authorize(String)
         */
        protected virtual AuthToken GetAccessToken(AuthCallback authCallback)
        {
            throw new System.NotImplementedException();
        }

        /**
         * 使用token换取用户信息
         *
         * @param authToken token信息
         * @return 用户信息
         * @see AuthDefaultRequest#getAccessToken(AuthCallback)
         */
        protected virtual AuthUser GetUserInfo(AuthToken authToken)
        {
            throw new System.NotImplementedException();
        }


        /**
         * 返回授权url，可自行跳转页面
         * <p>
         * 不建议使用该方式获取授权地址，不带{@code state}的授权地址，容易受到csrf攻击。
         * 建议使用{@link AuthDefaultRequest#authorize(String)}方法生成授权地址，在回调方法中对{@code state}进行校验
         *
         * @return 返回授权地址
         * @see AuthDefaultRequest#authorize(String)
         */
        public virtual string Authorize()
        {
            return this.Authorize(null);
        }

        /**
         * 返回带{@code state}参数的授权url，授权回调时会带上这个{@code state}
         *
         * @param state state 验证授权流程的参数，可以防止csrf
         * @return 返回授权地址
         * @since 1.9.3
         */
        public virtual string Authorize(string state)
        {
            return UrlBuilder.FromBaseUrl(source.Authorize())
                .QueryParam("response_type", "code")
                .QueryParam("client_id", config.ClientId)
                .QueryParam("redirect_uri", config.RedirectUri)
                .QueryParam("state", GetRealState(state))
                .Build();
        }


        /**
         * 返回获取accessToken的url
         *
         * @param code 授权码
         * @return 返回获取accessToken的url
         */
        protected virtual string accessTokenUrl(string code)
        {
            return UrlBuilder.FromBaseUrl(source.AccessToken())
                .QueryParam("code", code)
                .QueryParam("client_id", config.ClientId)
                .QueryParam("client_secret", config.ClientSecret)
                .QueryParam("grant_type", "authorization_code")
                .QueryParam("redirect_uri", config.RedirectUri)
                .Build();
        }


        /**
         * 返回获取accessToken的url
         *
         * @param refreshToken refreshToken
         * @return 返回获取accessToken的url
         */
        protected virtual string RefreshTokenUrl(string refreshToken)
        {
            return UrlBuilder.FromBaseUrl(source.Refresh())
                .QueryParam("client_id", config.ClientId)
                .QueryParam("client_secret", config.ClientSecret)
                .QueryParam("refresh_token", refreshToken)
                .QueryParam("grant_type", "refresh_token")
                .QueryParam("redirect_uri", config.RedirectUri)
                .Build();
        }

        /**
         * 返回获取userInfo的url
         *
         * @param authToken token
         * @return 返回获取userInfo的url
         */
        protected virtual string UserInfoUrl(AuthToken authToken)
        {
            return UrlBuilder.FromBaseUrl(source.UserInfo()).QueryParam("access_token", authToken.AccessToken).Build();
        }
        public virtual AuthResponse Login(AuthCallback authCallback)
        {
            try
            {
                AuthChecker.CheckCode(source, authCallback);
                AuthChecker.CheckState(authCallback.State, source, authStateCache);

                AuthToken authToken = this.GetAccessToken(authCallback);
                AuthUser user = this.GetUserInfo(authToken);
                return new AuthResponse(Convert.ToInt32(AuthResponseStatus.SUCCESS), null, user);
            }
            catch (Exception e)
            {
                return this.ResponseError(e);
            }
        }

        /**
         * 返回获取revoke authorization的url
         *
         * @param authToken token
         * @return 返回获取revoke authorization的url
         */
        protected virtual string RevokeUrl(AuthToken authToken)
        {
            return UrlBuilder.FromBaseUrl(source.Revoke()).QueryParam("access_token", authToken.AccessToken).Build();
        }

        /**
        * 获取state，如果为空， 则默认取当前日期的时间戳
        *
        * @param state 原始的state
        * @return 返回不为null的state
        */
        protected virtual string GetRealState(string state)
        {
            if (string.IsNullOrWhiteSpace(state))
            {
                state = Guid.NewGuid().ToString();
            }
            // 缓存state
            authStateCache.Cache(state, state);
            return state;
        }


        /**
         * 处理{@link AuthDefaultRequest#login(AuthCallback)} 发生异常的情况，统一响应参数
         *
         * @param e 具体的异常
         * @return AuthResponse
         */
        private AuthResponse ResponseError(Exception e)
        {
            int errorCode = Convert.ToInt32(AuthResponseStatus.FAILURE);
            string errorMsg = e.Message;
            return new AuthResponse(errorCode, errorMsg);
        }



        /**
        * 通用的 authorizationCode 协议
        *
        * @param code code码
        * @return HttpResponse
        */
        protected virtual string DoPostAuthorizationCode(string code)
        {
            return HttpUtils.RequestPost(accessTokenUrl(code));
        }

        /**
         * 通用的 authorizationCode 协议
         *
         * @param code code码
         * @return HttpResponse
         */
        protected virtual string DoGetAuthorizationCode(String code)
        {
            return HttpUtils.RequestGet(accessTokenUrl(code));
        }

        /**
         * 通用的 用户信息
         *
         * @param authToken token封装
         * @return HttpResponse
         */
        protected virtual string DoPostUserInfo(AuthToken authToken)
        {
            return HttpUtils.RequestPost(UserInfoUrl(authToken));
        }

        /**
         * 通用的 用户信息
         *
         * @param authToken token封装
         * @return HttpResponse
         */
        protected virtual string DoGetUserInfo(AuthToken authToken)
        {
            return HttpUtils.RequestGet(UserInfoUrl(authToken));
        }

        /**
         * 通用的post形式的取消授权方法
         *
         * @param authToken token封装
         * @return HttpResponse
         */
        protected virtual string DoPostRevoke(AuthToken authToken)
        {
            return HttpUtils.RequestPost(RevokeUrl(authToken));
        }

        /**
         * 通用的post形式的取消授权方法
         *
         * @param authToken token封装
         * @return HttpResponse
         */
        protected virtual string DoGetRevoke(AuthToken authToken)
        {
            return HttpUtils.RequestGet(RevokeUrl(authToken));
        }

    }
}