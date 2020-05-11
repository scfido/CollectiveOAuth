using Come.CollectiveOAuth.Cache;
using Come.CollectiveOAuth.Config;
using Come.CollectiveOAuth.Models;
using Come.CollectiveOAuth.Utils;
using System;
using System.Collections.Generic;
using System.Linq;
using Come.CollectiveOAuth.Enums;

namespace Come.CollectiveOAuth.Request
{
    public class ToutiaoAuthRequest : DefaultAuthRequest
    {
        public ToutiaoAuthRequest(ClientConfig config) : base(config, new ToutiaoAuthSource())
        {
        }

        public ToutiaoAuthRequest(ClientConfig config, IAuthStateCache authStateCache)
            : base(config, new ToutiaoAuthSource(), authStateCache)
        {
        }

        protected override AuthToken GetAccessToken(AuthCallback authCallback)
        {
            var response = DoGetAuthorizationCode(authCallback.Code);
            var accessTokenObject = response.ParseObject();

            this.CheckResponse(accessTokenObject);

            var authToken = new AuthToken();
            authToken.AccessToken = accessTokenObject.GetString("access_token");
            authToken.ExpireIn = accessTokenObject.GetInt32("expires_in");
            authToken.OpenId = accessTokenObject.GetString("open_id");
            authToken.Code = authCallback.Code;
            return authToken;
        }

        protected override AuthUser GetUserInfo(AuthToken authToken)
        {
            string userResponse = DoGetUserInfo(authToken);
            var userProfile = userResponse.ParseObject();
            this.CheckResponse(userProfile);

            var userObj = userProfile.GetString("data").ParseObject();

            bool isAnonymousUser = userObj.GetInt32("uid_type") == 14;
            string anonymousUserName = "匿名用户";

            var authUser = new AuthUser();
            authUser.Uuid = userObj.GetString("uid");
            authUser.Username = isAnonymousUser ? anonymousUserName : userObj.GetString("screen_name");
            authUser.Nickname = isAnonymousUser ? anonymousUserName : userObj.GetString("screen_name");
            authUser.Avatar = userObj.GetString("avatar_url");
            authUser.Remark = userObj.GetString("description");
            authUser.Gender = GlobalAuthUtil.GetRealGender(userObj.GetString("gender"));
            authUser.Token = authToken;
            authUser.Source = source.GetName();
            authUser.OriginalUser = userProfile;
            authUser.OriginalUserStr = userResponse;
            return authUser;
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
                .QueryParam("client_key", config.ClientId)
                .QueryParam("redirect_uri", config.RedirectUri)
                .QueryParam("auth_only", 1)
                .QueryParam("display", 0)
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
                .QueryParam("code", code)
                .QueryParam("client_key", config.ClientId)
                .QueryParam("client_secret", config.ClientSecret)
                .QueryParam("grant_type", "authorization_code")
                .Build();
        }

        /**
         * 返回获取userInfo的url
         *
         * @param authToken 用户授权后的token
         * @return 返回获取userInfo的url
         */
        protected override string UserInfoUrl(AuthToken authToken)
        {
            return UrlBuilder.FromBaseUrl(source.UserInfo())
                .QueryParam("client_key", config.ClientId)
                .QueryParam("access_token", authToken.AccessToken)
                .Build();
        }

        /**
       * 校验请求结果
       *
       * @param response 请求结果
       * @return 如果请求结果正常，则返回Exception
       */
        private void CheckResponse(Dictionary<string, object> dic)
        {
            if (dic.ContainsKey("error_code"))
            {
                throw new Exception(GetToutiaoErrorCode(dic.GetInt32("error_code")).GetDesc());
            }
        }

        private AuthToutiaoErrorCode GetToutiaoErrorCode(int errorCode)
        {
            var enumObjects = typeof(AuthToutiaoErrorCode).ToList();
            var codeEnum = enumObjects.Where(a => a.ID == errorCode).ToList();
            if (codeEnum.Count > 0)
            {
                return GlobalAuthUtil.EnumFromString<AuthToutiaoErrorCode>(codeEnum[0].Name);
            }
            else
            {
                return AuthToutiaoErrorCode.EC999;
            }
        }
    }
}