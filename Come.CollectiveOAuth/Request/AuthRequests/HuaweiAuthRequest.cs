using Come.CollectiveOAuth.Cache;
using Come.CollectiveOAuth.Config;
using Come.CollectiveOAuth.Models;
using Come.CollectiveOAuth.Utils;
using System;
using System.Collections.Generic;
using Come.CollectiveOAuth.Enums;

namespace Come.CollectiveOAuth.Request
{
    public class HuaweiAuthRequest : DefaultAuthRequest
    {
        public HuaweiAuthRequest(ClientConfig config) : base(config, new HuaweiAuthSource())
        {
        }

        public HuaweiAuthRequest(ClientConfig config, IAuthStateCache authStateCache)
            : base(config, new HuaweiAuthSource(), authStateCache)
        {
        }

        /**
        * 获取access token
        *
        * @param authCallback 授权成功后的回调参数
        * @return token
        * @see AuthDefaultRequest#authorize()
        * @see AuthDefaultRequest#authorize(String)
        */
        protected override AuthToken GetAccessToken(AuthCallback authCallback)
        {
            var reqParams = new Dictionary<string, object>
            {
                { "grant_type", "authorization_code" },
                { "code", authCallback.AuthorizationCode },
                { "client_id", config.ClientId },
                { "client_secret", config.ClientSecret },
                { "redirect_uri", config.RedirectUri },
            };

            var response = HttpUtils.RequestFormPost(source.AccessToken(), reqParams.SpellParams());

            return getAuthToken(response);
        }

        /**
         * 使用token换取用户信息
         *
         * @param authToken token信息
         * @return 用户信息
         * @see AuthDefaultRequest#getAccessToken(AuthCallback)
         */
        protected override AuthUser GetUserInfo(AuthToken authToken)
        {
            var reqParams = new Dictionary<string, object>
            {
                { "nsp_ts", DateTime.Now.Ticks },
                { "access_token", authToken.AccessToken },
                { "nsp_fmt", "JS" },
                { "nsp_svc", "OpenUP.User.getInfo" },
            };

            var response = HttpUtils.RequestFormPost(source.UserInfo(), reqParams.SpellParams());
            var userObj = response.ParseObject();

            this.checkResponse(userObj);

            AuthUserGender gender = getRealGender(userObj);

            var authUser = new AuthUser();
            authUser.Uuid = userObj.GetString("userID");
            authUser.Username = userObj.GetString("userName");
            authUser.Nickname = userObj.GetString("userName");
            authUser.Gender = gender;
            authUser.Avatar = userObj.GetString("headPictureURL");
          
            authUser.Token = authToken;
            authUser.Source = source.GetName();
            authUser.OriginalUser = userObj;
            authUser.OriginalUserStr = response;
            return authUser;
        }

        /**
         * 刷新access token （续期）
         *
         * @param authToken 登录成功后返回的Token信息
         * @return AuthResponse
         */
        public override AuthResponse Refresh(AuthToken authToken)
        {
            var reqParams = new Dictionary<string, object>
            {
                { "client_id", config.ClientId },
                { "client_secret", config.ClientSecret },
                { "refresh_token", authToken.RefreshToken },
                { "grant_type", "refresh_token" },
            };
            var response = HttpUtils.RequestFormPost(source.Refresh(), reqParams.SpellParams());

            return new AuthResponse(AuthResponseStatus.SUCCESS.GetCode(), AuthResponseStatus.SUCCESS.GetDesc(), getAuthToken(response));
        }

        private AuthToken getAuthToken(string response)
        {
            var authTokenObj = response.ParseObject();

            this.checkResponse(authTokenObj);

            var authToken = new AuthToken();
            authToken.AccessToken = authTokenObj.GetString("access_token");
            authToken.RefreshToken = authTokenObj.GetString("refresh_token");
            authToken.ExpireIn = authTokenObj.GetInt32("expires_in");
            return authToken;
        }

        /**
         * 返回带{@code state}参数的授权url，授权回调时会带上这个{@code state}
         *
         * @param state state 验证授权流程的参数，可以防止csrf
         * @return 返回授权地址
         * @since 1.9.3
         */
        public override string Authorize(string state)
        {
            return UrlBuilder.FromBaseUrl(source.Authorize())
                .QueryParam("response_type", "code")
                .QueryParam("client_id", config.ClientId)
                .QueryParam("redirect_uri", config.RedirectUri)
                .QueryParam("access_type", "offline")
                .QueryParam("scope", config.Scope.IsNullOrWhiteSpace() ? "https%3A%2F%2Fwww.huawei.com%2Fauth%2Faccount%2Fbase.profile" : config.Scope)
                .QueryParam("state", GetRealState(state))
                .Build();
        }

        /**
         * 返回获取accessToken的url
         *
         * @param code 授权码
         * @return 返回获取accessToken的url
         */
        protected override string accessTokenUrl(string code)
        {
            return UrlBuilder.FromBaseUrl(source.AccessToken())
                .QueryParam("grant_type", "authorization_code")
                .QueryParam("code", code)
                .QueryParam("client_id", config.ClientId)
                .QueryParam("client_secret", config.ClientSecret)
                .QueryParam("redirect_uri", config.RedirectUri)
                .Build();
        }

        /**
         * 返回获取userInfo的url
         *
         * @param authToken token
         * @return 返回获取userInfo的url
         */
        protected override string UserInfoUrl(AuthToken authToken)
        {
            return UrlBuilder.FromBaseUrl(source.UserInfo())
                .QueryParam("nsp_ts", DateTime.Now.Ticks)
                .QueryParam("access_token", authToken.AccessToken)
                .QueryParam("nsp_fmt", "JS")
                .QueryParam("nsp_svc", "OpenUP.User.getInfo")
                .Build();
        }

        /**
         * 获取用户的实际性别。华为系统中，用户的性别：1表示女，0表示男
         *
         * @param object obj
         * @return AuthUserGender
         */
        private AuthUserGender getRealGender(Dictionary<string, object> userObj)
        {
            int genderCodeInt = userObj.GetInt32("gender");
            string genderCode = genderCodeInt == 1 ? "0" : (genderCodeInt == 0) ? "1" : genderCodeInt + "";
            return GlobalAuthUtil.GetRealGender(genderCode);
        }

        /**
         * 校验响应结果
         *
         * @param object 接口返回的结果
         */
        private void checkResponse(Dictionary<string, object> dic)
        {
            if (dic.ContainsKey("NSP_STATUS"))
            {
                throw new Exception(dic.GetString("error"));
            }
            if (dic.ContainsKey("error"))
            {
                throw new Exception(dic.GetString("sub_error") + ":" + dic.GetString("error_description"));
            }
        }
    }
}