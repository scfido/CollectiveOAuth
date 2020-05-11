using Come.CollectiveOAuth.Cache;
using Come.CollectiveOAuth.Config;
using Come.CollectiveOAuth.Enums;
using Come.CollectiveOAuth.Models;
using Come.CollectiveOAuth.Utils;
using System;
using System.Collections.Generic;

namespace Come.CollectiveOAuth.Request
{
    public class BaiduAuthRequest : DefaultAuthRequest
    {
        public BaiduAuthRequest(ClientConfig config) : base(config, new BaiduAuthSource())
        {
        }

        public BaiduAuthRequest(ClientConfig config, IAuthStateCache authStateCache)
            : base(config, new BaiduAuthSource(), authStateCache)
        {
        }

        protected override AuthToken GetAccessToken(AuthCallback authCallback)
        {
            string response = DoPostAuthorizationCode(authCallback.Code);
            var accessTokenObject = response.ParseObject();
            this.checkResponse(accessTokenObject);

            var authToken = new AuthToken();
            authToken.AccessToken = accessTokenObject.GetString("access_token");
            authToken.RefreshToken = accessTokenObject.GetString("refresh_token");
            authToken.ExpireIn = accessTokenObject.GetInt32("expires_in");
            authToken.Scope = accessTokenObject.GetString("scope");

            return authToken;
        }

        protected override AuthUser GetUserInfo(AuthToken authToken)
        {
            string response = DoGetUserInfo(authToken);
            var userObj = response.ParseObject();
            this.checkResponse(userObj);

            var authUser = new AuthUser();
            authUser.Uuid = userObj.GetString("userid");
            authUser.Username = userObj.GetString("username");
            authUser.Nickname = userObj.GetString("username");

            string protrait = userObj.GetString("portrait");
            authUser.Avatar = protrait.IsNullOrWhiteSpace() ? null : string.Format("http://himg.bdimg.com/sys/portrait/item/{0}.jpg", protrait);

            authUser.Remark = userObj.GetString("userdetail");
            authUser.Gender = GlobalAuthUtil.GetRealGender(userObj.GetString("sex"));

            authUser.Token = authToken;
            authUser.Source = source.GetName();
            authUser.OriginalUser = userObj;
            authUser.OriginalUserStr = response;
            return authUser;
        }

        public override AuthResponse revoke(AuthToken authToken)
        {
            string response = DoGetRevoke(authToken);
            var revokeObj = response.ParseObject();
            this.checkResponse(revokeObj);
            // 返回1表示取消授权成功，否则失败
            AuthResponseStatus status = revokeObj.GetInt32("result") == 1 ? AuthResponseStatus.SUCCESS : AuthResponseStatus.FAILURE;
            return new AuthResponse(status.GetCode(), status.GetDesc());
        }

        public override AuthResponse Refresh(AuthToken authToken)
        {
            string refreshUrl = UrlBuilder.FromBaseUrl(this.source.Refresh())
                .QueryParam("grant_type", "refresh_token")
                .QueryParam("refresh_token", authToken.RefreshToken)
                .QueryParam("client_id", this.config.ClientId)
                .QueryParam("client_secret", this.config.ClientSecret)
                .Build();
            string response = HttpUtils.RequestGet(refreshUrl);
            var accessTokenObject = response.ParseObject();
            this.checkResponse(accessTokenObject);

            var newAuthToken = new AuthToken();
            newAuthToken.AccessToken = accessTokenObject.GetString("access_token");
            newAuthToken.RefreshToken = accessTokenObject.GetString("refresh_token");
            newAuthToken.ExpireIn = accessTokenObject.GetInt32("expires_in");
            newAuthToken.Scope = accessTokenObject.GetString("scope");

            return new AuthResponse(AuthResponseStatus.SUCCESS.GetCode(), AuthResponseStatus.SUCCESS.GetDesc(), newAuthToken);
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
                .QueryParam("display", "page")
                .QueryParam("scope", "basic")
                .QueryParam("state", GetRealState(state))
                .Build();
        }

        /**
         * 校验请求结果
         *
         * @param response 请求结果
         * @return 如果请求结果正常，则返回JSONObject
         */
        private void checkResponse(Dictionary<string, object> dic)
        {
            if (dic.ContainsKey("error") || dic.ContainsKey("error_code"))
            {
                throw new Exception($@"error_code: {dic.GetString("error_code")}," +
                    $" error_description: {dic.GetString("error_description")}," +
                    $" error_msg: {dic.GetString("error_msg")}");
            }
        }
    }
}