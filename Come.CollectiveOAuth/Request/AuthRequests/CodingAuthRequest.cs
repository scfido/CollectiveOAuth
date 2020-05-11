using Come.CollectiveOAuth.Cache;
using Come.CollectiveOAuth.Config;
using Come.CollectiveOAuth.Models;
using Come.CollectiveOAuth.Utils;
using System;
using System.Collections.Generic;
using System.Net;
using Come.CollectiveOAuth.Enums;

namespace Come.CollectiveOAuth.Request
{
    public class CodingAuthRequest : DefaultAuthRequest
    {
        public CodingAuthRequest(ClientConfig config) : base(config, new CodingAuthSource())
        {
        }

        public CodingAuthRequest(ClientConfig config, IAuthStateCache authStateCache)
            : base(config, new CodingAuthSource(), authStateCache)
        {
        }

        protected override AuthToken GetAccessToken(AuthCallback authCallback)
        {
            string response = DoGetAuthorizationCode(authCallback.Code);
            var accessTokenObject = response.ParseObject();
            this.checkResponse(accessTokenObject);

            var authToken = new AuthToken();
            authToken.AccessToken = accessTokenObject.GetString("access_token");
            authToken.ExpireIn = accessTokenObject.GetInt32("expires_in");
            authToken.RefreshToken = accessTokenObject.GetString("refresh_token");
            return authToken;
        }

        protected override AuthUser GetUserInfo(AuthToken authToken)
        {
            string response = DoGetUserInfo(authToken);
            var resData = response.ParseObject();
            this.checkResponse(resData);

            var userObj = resData.GetString("data").ParseObject();

            var authUser = new AuthUser();
            authUser.Uuid = userObj.GetString("id");
            authUser.Username = userObj.GetString("name");
            authUser.Nickname = userObj.GetString("name");
            authUser.Avatar = $"{"https://coding.net/"}{userObj.GetString("avatar")}";
            authUser.Blog = $"{"https://coding.net/"}{userObj.GetString("path")}";
            authUser.Company = userObj.GetString("company");
            authUser.Location = userObj.GetString("location");
            authUser.Email = userObj.GetString("email");
            authUser.Remark = userObj.GetString("slogan");
            authUser.Gender = GlobalAuthUtil.GetRealGender(userObj.GetString("sex"));

            authUser.Token = authToken;
            authUser.Source = source.GetName();
            authUser.OriginalUser = resData;
            authUser.OriginalUserStr = response;
            return authUser;
        }

        protected override string DoGetUserInfo(AuthToken authToken)
        {
            ServicePointManager.SecurityProtocol = SecurityProtocolType.Tls12;
            return HttpUtils.RequestJsonGet(UserInfoUrl(authToken));
        }

        protected override string DoGetAuthorizationCode(String code)
        {
            ServicePointManager.SecurityProtocol = SecurityProtocolType.Tls12;
            return HttpUtils.RequestJsonGet(accessTokenUrl(code));
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
                .QueryParam("scope", config.Scope.IsNullOrWhiteSpace() ? "user" : config.Scope)
                .QueryParam("state", GetRealState(state))
                .Build();
        }
        /**
        * 校验请求结果
        *
        * @param response 请求结果
        * @return 如果请求结果正常，则返回Exception
        */
        private void checkResponse(Dictionary<string, object> dic)
        {
            if (dic.ContainsKey("code") && dic.GetInt32("code") != 0)
            {
                throw new Exception($"{dic.GetString("msg")}");
            }
        }
    }
}