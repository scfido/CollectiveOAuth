using Come.CollectiveOAuth.Cache;
using Come.CollectiveOAuth.Config;
using Come.CollectiveOAuth.Models;
using Come.CollectiveOAuth.Utils;
using System;
using System.Collections.Generic;
using Come.CollectiveOAuth.Enums;

namespace Come.CollectiveOAuth.Request
{
    public class RenrenAuthRequest : DefaultAuthRequest
    {
        public RenrenAuthRequest(ClientConfig config) : base(config, new RenrenAuthSource())
        {
        }

        public RenrenAuthRequest(ClientConfig config, IAuthStateCache authStateCache)
            : base(config, new RenrenAuthSource(), authStateCache)
        {
        }

        protected override AuthToken GetAccessToken(AuthCallback authCallback)
        {
            return this.getToken(accessTokenUrl(authCallback.Code));
        }

        protected override AuthUser GetUserInfo(AuthToken authToken)
        {
            var response = DoGetUserInfo(authToken);
            var userObj = response.ParseObject().GetJSONObject("response");

            var authUser = new AuthUser();
            authUser.Uuid = userObj.GetString("id");
            authUser.Username = userObj.GetString("name");
            authUser.Nickname = userObj.GetString("name");
            authUser.Avatar = getAvatarUrl(userObj);
            authUser.Company = getCompany(userObj);
            authUser.Gender = getGender(userObj);

            authUser.Token = authToken;
            authUser.Source = source.GetName();
            authUser.OriginalUser = userObj;
            authUser.OriginalUserStr = response;
            return authUser;
        }

        public override AuthResponse Refresh(AuthToken authToken)
        {
            var token = getToken(this.RefreshTokenUrl(authToken.RefreshToken));
            return new AuthResponse(AuthResponseStatus.SUCCESS.GetCode(), AuthResponseStatus.SUCCESS.GetDesc(), token);
        }

        private AuthToken getToken(string url)
        {
            var response = HttpUtils.RequestPost(url);
            var jsonObject = response.ParseObject();
            if (jsonObject.ContainsKey("error"))
            {
                throw new Exception("Failed to get token from Renren: " + jsonObject);
            }

            var authToken = new AuthToken();
            authToken.AccessToken = jsonObject.GetString("access_token");
            authToken.TokenType = jsonObject.GetString("token_type");
            authToken.ExpireIn = jsonObject.GetInt32("expires_in");
            authToken.RefreshToken = jsonObject.GetString("refresh_token");
            authToken.OpenId = jsonObject.GetJSONObject("user").GetString("id");

            return authToken;
        }

        private string getAvatarUrl(Dictionary<string, object> userObj)
        {
            var jsonArray = userObj.GetJSONArray("avatar");
            if (jsonArray.Count == 0)
            {
                return null;
            }
            return jsonArray[0].GetString("url");
        }

        private AuthUserGender getGender(Dictionary<string, object> userObj)
        {
            var basicInformation = userObj.GetJSONObject("basicInformation");
            if (basicInformation.Count == 0)
            {
                return AuthUserGender.Unknown;
            }
            return GlobalAuthUtil.GetRealGender(basicInformation.GetString("sex"));
        }

        private string getCompany(Dictionary<string, object> userObj)
        {
            var jsonArray = userObj.GetJSONArray("work");
            if (jsonArray.Count == 0)
            {
                return null;
            }
            return jsonArray[0].GetString("name");
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
                .QueryParam("access_token", authToken.AccessToken)
                .QueryParam("userId", authToken.OpenId)
                .Build();
        }

        public override string Authorize(string state)
        {
            return UrlBuilder.FromBaseUrl(source.Authorize())
                .QueryParam("response_type", "code")
                .QueryParam("client_id", config.ClientId)
                .QueryParam("redirect_uri", config.RedirectUri)
                .QueryParam("state", GetRealState(state))
                .QueryParam("display", "page")
                .Build();
        }
    }
}