using Come.CollectiveOAuth.Cache;
using Come.CollectiveOAuth.Config;
using Come.CollectiveOAuth.Models;
using Come.CollectiveOAuth.Utils;
using System;
using System.Collections.Generic;
using Come.CollectiveOAuth.Enums;

namespace Come.CollectiveOAuth.Request
{
    public class WeiboAuthRequest : DefaultAuthRequest
    {
        public WeiboAuthRequest(ClientConfig config) : base(config, new WeiboAuthSource())
        {
        }

        public WeiboAuthRequest(ClientConfig config, IAuthStateCache authStateCache)
            : base(config, new WeiboAuthSource(), authStateCache)
        {
        }

        protected override AuthToken GetAccessToken(AuthCallback authCallback)
        {
            var response = DoPostAuthorizationCode(authCallback.Code);
            var accessTokenObject = response.ParseObject();
            if (accessTokenObject.ContainsKey("error"))
            {
                throw new Exception(accessTokenObject.GetString("error_description"));
            }

            var authToken = new AuthToken();
            authToken.AccessToken = accessTokenObject.GetString("access_token");
            authToken.Uid = accessTokenObject.GetString("uid");
            authToken.OpenId = accessTokenObject.GetString("uid");
            authToken.ExpireIn = accessTokenObject.GetInt32("expires_in");
            authToken.Code = authCallback.Code;

            return authToken;
        }

        protected override AuthUser GetUserInfo(AuthToken authToken)
        {
            var accessToken = authToken.AccessToken;
            var uid = authToken.Uid;
            var oauthParam = $"uid={uid}&access_token={accessToken}";
            var reqParams = new Dictionary<string, object>();
            reqParams.Add("Authorization", "OAuth2 " + oauthParam);
            reqParams.Add("API-RemoteIP", "application/x-www-form-urlencoded");

            string response = HttpUtils.RequestGet(UserInfoUrl(authToken), reqParams);
          
            var userObj = response.ParseObject();
            if (userObj.ContainsKey("error"))
            {
                throw new Exception(userObj.GetString("error"));
            }

            var authUser = new AuthUser();
            authUser.Uuid = userObj.GetString("id");
            authUser.Username = userObj.GetString("name");
            authUser.Nickname = userObj.GetString("screen_name");
            authUser.Avatar = userObj.GetString("profile_image_url");
            authUser.Blog = userObj.GetString("url").IsNullOrWhiteSpace() ? $"{"https://weibo.com/"}{userObj.GetString("profile_url")}" : userObj.GetString("url");
            authUser.Location = userObj.GetString("location");
            authUser.Remark = userObj.GetString("description");
            authUser.Gender = GlobalAuthUtil.GetRealGender(userObj.GetString("gender"));

            authUser.Token = authToken;
            authUser.Source = source.GetName();
            authUser.OriginalUser = userObj;
            authUser.OriginalUserStr = response;
            return authUser;
        }

        /**
         * 返回获取userInfo的url
         *
         * @param authToken authToken
         * @return 返回获取userInfo的url
         */
        protected override string UserInfoUrl(AuthToken authToken)
        {
            return UrlBuilder.FromBaseUrl(source.UserInfo())
                .QueryParam("access_token", authToken.AccessToken)
                .QueryParam("uid", authToken.Uid)
                .Build();
        }

        public override AuthResponse revoke(AuthToken authToken)
        {
            var response = DoGetRevoke(authToken);
            var retObj = response.ParseObject();
            if (retObj.ContainsKey("error"))
            {
                return new AuthResponse(AuthResponseStatus.FAILURE.GetCode(), retObj.GetString("error"));
            }
            // 返回 result = true 表示取消授权成功，否则失败
            AuthResponseStatus status = retObj.GetBool("result") ? AuthResponseStatus.SUCCESS : AuthResponseStatus.FAILURE;
            return new AuthResponse(status.GetCode(), status.GetDesc());
        }
    }
}