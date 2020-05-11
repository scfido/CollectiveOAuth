using Come.CollectiveOAuth.Cache;
using Come.CollectiveOAuth.Config;
using Come.CollectiveOAuth.Models;
using Come.CollectiveOAuth.Utils;
using System;
using System.Collections.Generic;
using Come.CollectiveOAuth.Enums;

namespace Come.CollectiveOAuth.Request
{
    public class KujialeAuthRequest : DefaultAuthRequest
    {
        public KujialeAuthRequest(ClientConfig config) : base(config, new KujialeAuthSource())
        {
        }

        public KujialeAuthRequest(ClientConfig config, IAuthStateCache authStateCache)
            : base(config, new KujialeAuthSource(), authStateCache)
        {
        }

        /**
          * 返回带{@code state}参数的授权url，授权回调时会带上这个{@code state}
          * 默认只向用户请求用户信息授权
          *
          * @param state state 验证授权流程的参数，可以防止csrf
          * @return 返回授权地址
          * @since 1.11.0
          */
        public override string Authorize(string state)
        {
             var urlBuilder = UrlBuilder.FromBaseUrl(source.Authorize())
                .QueryParam("response_type", "code")
                .QueryParam("client_id", config.ClientId)
                .QueryParam("redirect_uri", config.RedirectUri)
                .QueryParam("state", GetRealState(state))
                .QueryParam("scope", config.Scope.IsNullOrWhiteSpace() ? "get_user_info": config.Scope)
                .Build();
             return urlBuilder;
        }

        protected override AuthToken GetAccessToken(AuthCallback authCallback)
        {
            var response = DoPostAuthorizationCode(authCallback.Code);
            return getAuthToken(response);
        }

        private AuthToken getAuthToken(string response)
        {
            var accessTokenObject = response.ParseObject();
            this.checkResponse(accessTokenObject);

            var resultObject = accessTokenObject.GetJSONObject("d");

            var authToken = new AuthToken();
            authToken.AccessToken = resultObject.GetString("accessToken");
            authToken.RefreshToken = resultObject.GetString("refreshToken");
            authToken.ExpireIn = resultObject.GetInt32("expiresIn");
            return authToken;
        }

        
        protected override AuthUser GetUserInfo(AuthToken authToken)
        {
            string openId = this.getOpenId(authToken);

            var userInfoUrl = UrlBuilder.FromBaseUrl(source.UserInfo())
                .QueryParam("access_token", authToken.AccessToken)
                .QueryParam("open_id", openId)
                .Build();

            var response = HttpUtils.RequestGet(userInfoUrl);
            var resObj = response.ParseObject();
            this.checkResponse(resObj);

            var userObj = resObj.GetJSONObject("d");

            var authUser = new AuthUser();
            authUser.Uuid = userObj.GetString("openId");
            authUser.Username = userObj.GetString("userName");
            authUser.Nickname = userObj.GetString("userName");
            authUser.Avatar = userObj.GetString("avatar");
            authUser.Gender = AuthUserGender.Unknown;

            authUser.Token = authToken;
            authUser.Source = source.GetName();
            authUser.OriginalUser = resObj;
            authUser.OriginalUserStr = response;
            return authUser;
        }

        /**
         * 获取酷家乐的openId，此id在当前client范围内可以唯一识别授权用户
         *
         * @param authToken 通过{@link AuthKujialeRequest#getAccessToken(AuthCallback)}获取到的{@code authToken}
         * @return openId
         */
        private string getOpenId(AuthToken authToken)
        {
            var openIdUrl = UrlBuilder.FromBaseUrl("https://oauth.kujiale.com/oauth2/auth/user")
                .QueryParam("access_token", authToken.AccessToken)
                .Build();
            var response = HttpUtils.RequestGet(openIdUrl);
            var accessTokenObject = response.ParseObject();
            this.checkResponse(accessTokenObject);
            return accessTokenObject.GetString("d");
        }

        public override AuthResponse Refresh(AuthToken authToken)
        {
            var refreshUrl = RefreshTokenUrl(authToken.RefreshToken);
            var response = HttpUtils.RequestPost(refreshUrl);
            return new AuthResponse(AuthResponseStatus.SUCCESS.GetCode(), AuthResponseStatus.SUCCESS.GetDesc(), getAuthToken(response));
        }

        /**
       * 校验请求结果
       *
       * @param response 请求结果
       * @return 如果请求结果正常，则返回Exception
       */
        private void checkResponse(Dictionary<string, object> dic)
        {
            if (dic.Count == 0)
            {
                throw new Exception("请求所返回的数据为空!");
            }

            if (!"0".Equals(dic.GetString("c")))
            {
                throw new Exception($"{dic.GetString("m")}");
            }
        }
    }
}