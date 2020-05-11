using Come.CollectiveOAuth.Config;
using Come.CollectiveOAuth.Models;
using Come.CollectiveOAuth.Utils;
using System;
using System.Collections.Generic;
using Come.CollectiveOAuth.Enums;
using Come.CollectiveOAuth.Cache;

namespace Come.CollectiveOAuth.Request
{
    public partial class WeChatOpenAuthRequest : DefaultAuthRequest
    {
        public WeChatOpenAuthRequest(ClientConfig config) : base(config, new WechatOpenAuthSource())
        {
        }

        public WeChatOpenAuthRequest(ClientConfig config, IAuthStateCache authStateCache) 
            : base(config, new WechatOpenAuthSource(), authStateCache)
        {
        }

        /**
          * 微信的特殊性，此时返回的信息同时包含 openid 和 access_token
          *
          * @param authCallback 回调返回的参数
          * @return 所有信息
          */
        protected override AuthToken GetAccessToken(AuthCallback authCallback)
        {
            return this.getToken(accessTokenUrl(authCallback.Code));
        }

        protected override AuthUser GetUserInfo(AuthToken authToken)
        {
            string openId = authToken.OpenId;

            string response = DoGetUserInfo(authToken);
            var jsonObj = response.ParseObject();

            this.checkResponse(jsonObj);

            //string location = String.format("%s-%s-%s", object.getString("country"), object.getString("province"), object.getString("city"));
            string location = $"{jsonObj.GetString("country")}-{jsonObj.GetString("province")}-{jsonObj.GetString("city")}";
            if (jsonObj.ContainsKey("unionid"))
            {
                authToken.UnionId = jsonObj.GetString("unionid");
            }

            var authUser = new AuthUser();

            authUser.Username = jsonObj.GetString("nickname");
            authUser.Nickname = jsonObj.GetString("nickname");
            authUser.Avatar = jsonObj.GetString("headimgurl");
            authUser.Location = location;
            authUser.Uuid = openId;
            authUser.Gender = GlobalAuthUtil.GetWechatRealGender(jsonObj.GetString("sex"));
            authUser.Token = authToken;
            authUser.Source = source.GetName();

            authUser.OriginalUser = jsonObj;
            authUser.OriginalUserStr = response;

            return authUser;
        }

        public override AuthResponse Refresh(AuthToken oldToken)
        {
            return new AuthResponse(Convert.ToInt32(AuthResponseStatus.SUCCESS), null, this.getToken(RefreshTokenUrl(oldToken.RefreshToken)));
        }

        /**
         * 检查响应内容是否正确
         *
         * @param object 请求响应内容
         */
        private void checkResponse(Dictionary<string, object> dic)
        {
            if (dic.ContainsKey("errcode"))
            {
                throw new Exception($"errcode: {dic.GetString("errcode")}, errmsg: {dic.GetString("errmsg")}");
            }
        }

        /**
         * 获取token，适用于获取access_token和刷新token
         *
         * @param accessTokenUrl 实际请求token的地址
         * @return token对象
         */
        private AuthToken getToken(string accessTokenUrl)
        {
            string response = HttpUtils.RequestGet(accessTokenUrl);
            var accessTokenObject = response.ParseObject();

            this.checkResponse(accessTokenObject);

            var authToken = new AuthToken();

            authToken.AccessToken = accessTokenObject.GetString("access_token");
            authToken.RefreshToken = accessTokenObject.GetString("refresh_token");
            authToken.ExpireIn = accessTokenObject.GetInt32("expires_in");
            authToken.OpenId = accessTokenObject.GetString("openid");

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
                .QueryParam("appid", config.ClientId)
                .QueryParam("redirect_uri", GlobalAuthUtil.UrlEncode(config.RedirectUri))
                .QueryParam("response_type", "code")
                .QueryParam("scope", config.Scope.IsNullOrWhiteSpace() ? "snsapi_login" : config.Scope)
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
                .QueryParam("appid", config.ClientId)
                .QueryParam("secret", config.ClientSecret)
                .QueryParam("code", code)
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
                .QueryParam("access_token", authToken.AccessToken)
                .QueryParam("openid", authToken.OpenId)
                .QueryParam("lang", "zh_CN")
                .Build();
        }

        /**
         * 返回获取userInfo的url
         *
         * @param refreshToken getAccessToken方法返回的refreshToken
         * @return 返回获取userInfo的url
         */
        protected override string RefreshTokenUrl(string refreshToken)
        {
            return UrlBuilder.FromBaseUrl(source.Refresh())
                .QueryParam("appid", config.ClientId)
                .QueryParam("grant_type", "refresh_token")
                .QueryParam("refresh_token", refreshToken)
                .Build();
        }
    }
}