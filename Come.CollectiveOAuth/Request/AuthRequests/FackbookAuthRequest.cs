using Come.CollectiveOAuth.Cache;
using Come.CollectiveOAuth.Config;
using Come.CollectiveOAuth.Models;
using Come.CollectiveOAuth.Utils;
using System;
using System.Collections.Generic;
using Come.CollectiveOAuth.Enums;

namespace Come.CollectiveOAuth.Request
{
    public class FackbookAuthRequest : DefaultAuthRequest
    {
        public FackbookAuthRequest(ClientConfig config) : base(config, new FackbookAuthSource())
        {
        }

        public FackbookAuthRequest(ClientConfig config, IAuthStateCache authStateCache)
            : base(config, new FackbookAuthSource(), authStateCache)
        {
        }

        protected override AuthToken GetAccessToken(AuthCallback authCallback)
        {
            var response = DoPostAuthorizationCode(authCallback.Code);
            var accessTokenObject = response.ParseObject();
            this.checkResponse(accessTokenObject);

            var authToken = new AuthToken
            {
                AccessToken = accessTokenObject.GetString("access_token"),
                ExpireIn = accessTokenObject.GetInt32("expires_in"),
                TokenType = accessTokenObject.GetString("token_type"),
                Code = authCallback.Code
            };
            return authToken;
        }

        protected override AuthUser GetUserInfo(AuthToken authToken)
        {
            var response = DoGetUserInfo(authToken);
            var userObj = response.ParseObject();
            this.checkResponse(userObj);

            var authUser = new AuthUser
            {
                Uuid = userObj.GetString("id"),
                Username = userObj.GetString("name"),
                Nickname = userObj.GetString("name"),
                Avatar = getUserPicture(userObj),
                Location = userObj.GetString("locale"),
                Email = userObj.GetString("email"),
                Gender = GlobalAuthUtil.GetRealGender(userObj.GetString("gender")),
                Token = authToken,
                Source = source.GetName(),
                OriginalUser = userObj,
                OriginalUserStr = response
            };
            return authUser;
        }

        private string getUserPicture(Dictionary<string, object> userObj)
        {
            string picture = null;
            if (userObj.ContainsKey("picture"))
            {
                var pictureObj = userObj.GetString("picture").ParseObject();
                pictureObj = pictureObj.GetString("data").ParseObject();
                if (null != pictureObj)
                {
                    picture = pictureObj.GetString("url");
                }
            }
            return picture;
        }

        /**
         * 返回获取userInfo的url
         *
         * @param authToken 用户token
         * @return 返回获取userInfo的url
         */
        protected override string UserInfoUrl(AuthToken authToken)
        {
            return UrlBuilder.FromBaseUrl(source.UserInfo())
                .QueryParam("access_token", authToken.AccessToken)
                .QueryParam("fields", "id,name,birthday,gender,hometown,email,devices,picture.width(400)")
                .Build();
        }


        /**
          * 检查响应内容是否正确
          *
          * @param object 请求响应内容
          */
        private void checkResponse(Dictionary<string, object> dic)
        {
            if (dic.ContainsKey("error"))
            {
                throw new Exception($"{dic.GetString("error").ParseObject().GetString("message")}");
            }
        }
    }
}