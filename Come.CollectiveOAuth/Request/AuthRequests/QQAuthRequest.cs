using Come.CollectiveOAuth.Cache;
using Come.CollectiveOAuth.Config;
using Come.CollectiveOAuth.Models;
using Come.CollectiveOAuth.Utils;
using System;
using System.Collections.Generic;
using Come.CollectiveOAuth.Enums;

namespace Come.CollectiveOAuth.Request
{
    public class QQAuthRequest : DefaultAuthRequest
    {
        public QQAuthRequest(ClientConfig config) : base(config, new QQAuthSource())
        {
        }

        public QQAuthRequest(ClientConfig config, IAuthStateCache authStateCache)
            : base(config, new QQAuthSource(), authStateCache)
        {
        }

        protected override AuthToken GetAccessToken(AuthCallback authCallback)
        {
            string response = DoGetAuthorizationCode(authCallback.Code);
            return getAuthToken(response);
        }

        public override AuthResponse Refresh(AuthToken authToken)
        {
            string response = HttpUtils.RequestGet(RefreshTokenUrl(authToken.RefreshToken));
            return new AuthResponse(AuthResponseStatus.SUCCESS.GetCode(), AuthResponseStatus.SUCCESS.GetDesc(), getAuthToken(response));
        }

        protected override AuthUser GetUserInfo(AuthToken authToken)
        {
            string openId = this.getOpenId(authToken);
            string response = DoGetUserInfo(authToken);
            var userObj = response.ParseObject();
            if (userObj.GetInt32("ret") != 0)
            {
                throw new Exception(userObj.GetString("msg"));
            }
            string avatar = userObj.GetString("figureurl_qq_2");
            if (avatar.IsNullOrWhiteSpace())
            {
                avatar = userObj.GetString("figureurl_qq_1");
            }

            string location = $"{userObj.GetString("province")}-{userObj.GetString("city")}";

            var authUser = new AuthUser();
            authUser.Uuid = openId;
            authUser.Username = userObj.GetString("nickname");
            authUser.Nickname = userObj.GetString("nickname");
            authUser.Avatar = avatar;
            authUser.Location = location;
            authUser.Email = userObj.GetString("email");
            authUser.Remark = userObj.GetString("bio");
            authUser.Gender = GlobalAuthUtil.GetRealGender(userObj.GetString("gender"));
            authUser.Token = authToken;
            authUser.Source = source.GetName();

            authUser.OriginalUser = userObj;
            authUser.OriginalUserStr = response;
            return authUser;
        }

        /**
         * 获取QQ用户的OpenId，支持自定义是否启用查询unionid的功能，如果启用查询unionid的功能，
         * 那就需要开发者先通过邮件申请unionid功能，参考链接 {@see http://wiki.connect.qq.com/unionid%E4%BB%8B%E7%BB%8D}
         *
         * @param authToken 通过{@link AuthQqRequest#getAccessToken(AuthCallback)}获取到的{@code authToken}
         * @return openId
         */
        private string getOpenId(AuthToken authToken)
        {
            var getOpenIdUrl = UrlBuilder.FromBaseUrl("https://graph.qq.com/oauth2.0/me")
                                .QueryParam("access_token", authToken.AccessToken)
                                .QueryParam("unionid", config.UnionId)
                                .Build();
            string response = HttpUtils.RequestGet(getOpenIdUrl);
            if (!response.IsNullOrWhiteSpace())
            {
                string body = response;
                string removePrefix = body.Replace("callback(", "");
                string removeSuffix = removePrefix.Replace(");", "");
                string openId = removeSuffix.Trim();
                var openIdObj = openId.ParseObject();
                if (openIdObj.ContainsKey("error"))
                {
                    throw new Exception(openIdObj.GetString("error") + ":" + openIdObj.GetString("error_description"));
                }
                authToken.OpenId = openIdObj.GetString("openid");
                if (openIdObj.ContainsKey("unionid"))
                {
                    authToken.UnionId = openIdObj.GetString("unionid");
                }

                return authToken.UnionId.IsNullOrWhiteSpace() ? authToken.OpenId : authToken.UnionId;
            }

            throw new Exception("request error");
        }

        /**
         * 返回获取userInfo的url
         *
         * @param authToken 用户授权token
         * @return 返回获取userInfo的url
         */
        protected override string UserInfoUrl(AuthToken authToken)
        {
            return UrlBuilder.FromBaseUrl(source.UserInfo())
                .QueryParam("access_token", authToken.AccessToken)
                .QueryParam("oauth_consumer_key", config.ClientId)
                .QueryParam("openid", authToken.OpenId)
                .Build();
        }

        private AuthToken getAuthToken(string response)
        {
            var accessTokenObject = response.ParseStringObject();
            if (!accessTokenObject.ContainsKey("access_token") || accessTokenObject.ContainsKey("code"))
            {
                throw new Exception(accessTokenObject.GetString("msg"));
            }
            var authToken = new AuthToken();
            authToken.AccessToken = accessTokenObject.GetString("access_token");
            authToken.ExpireIn = accessTokenObject.GetInt32("expires_in");
            authToken.RefreshToken = accessTokenObject.GetString("refresh_token");

            return authToken;
        }
    }
}