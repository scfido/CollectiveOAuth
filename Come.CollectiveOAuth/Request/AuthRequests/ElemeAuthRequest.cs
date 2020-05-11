using Come.CollectiveOAuth.Cache;
using Come.CollectiveOAuth.Config;
using Come.CollectiveOAuth.Models;
using Come.CollectiveOAuth.Utils;
using System;
using System.Collections.Generic;
using Come.CollectiveOAuth.Enums;
using System.Text;
using System.Security.Cryptography;
using Newtonsoft.Json;

namespace Come.CollectiveOAuth.Request
{
    public class ElemeAuthRequest : DefaultAuthRequest
    {
        public ElemeAuthRequest(ClientConfig config) : base(config, new ElemeAuthSource())
        {
        }

        public ElemeAuthRequest(ClientConfig config, IAuthStateCache authStateCache)
            : base(config, new ElemeAuthSource(), authStateCache)
        {
        }

        protected override AuthToken GetAccessToken(AuthCallback authCallback)
        {
            var reqParams = new Dictionary<string, object>
            {
                { "client_id", config.ClientId },
                { "redirect_uri", config.ClientSecret },
                { "code", authCallback.Code },
                { "grant_type", "authorization_code" },
            };

            var reqHeaders = this.getSpecialHeader(this.getRequestId());

            var response = HttpUtils.RequestFormPost(source.AccessToken(), reqParams.SpellParams(), reqHeaders);
            var accessTokenObject = response.ParseObject();

            this.checkResponse(accessTokenObject);

            var authToken = new AuthToken
            {
                AccessToken = accessTokenObject.GetString("access_token"),
                ExpireIn = accessTokenObject.GetInt32("expires_in"),
                RefreshToken = accessTokenObject.GetString("refresh_token"),
                TokenType = accessTokenObject.GetString("token_type"),
                Code = authCallback.Code
            };

            return authToken;
        }


        protected override AuthUser GetUserInfo(AuthToken authToken)
        {
            // 获取商户账号信息的API接口名称
            String action = "eleme.user.getUser";
            // 时间戳，单位秒。API服务端允许客户端请求最大时间误差为正负5分钟。
            long timestamp = DateTime.Now.Ticks;
            // 公共参数
            var metasHashMap = new Dictionary<string, object>();
            metasHashMap.Add("app_key", config.ClientId);
            metasHashMap.Add("timestamp", timestamp);
            string signature = this.generateElemeSignature(timestamp, action, authToken.AccessToken);
            string requestId = this.getRequestId();

            var paramsMap = new Dictionary<string, object>
            {
                { "nop", "1.0.0" },
                { "id", requestId },
                { "action", action },
                { "token", authToken.AccessToken },
                { "metas", JsonConvert.SerializeObject(metasHashMap) },
                { "params", "{}" },
                { "signature", signature }
            };

            var reqHeaders = new Dictionary<string, object>
            {
                { "Content-Type", "application/json; charset=utf-8" },
                { "Accept", "text/xml,text/javascript,text/html" },
                { "Accept-Encoding", "gzip" },
                { "User-Agent", "eleme-openapi-java-sdk"},
                { "x-eleme-requestid", requestId},
                { "Authorization", this.spliceBasicAuthStr()}
            };
            var response = HttpUtils.RequestPost(source.UserInfo(), JsonConvert.SerializeObject(paramsMap), reqHeaders);

            var resObj = response.ParseObject();

            // 校验请求
            if (resObj.ContainsKey("name"))
            {
                throw new Exception(resObj.GetString("message"));
            }
            if (resObj.ContainsKey("error") && !resObj.GetString("error").IsNullOrWhiteSpace())
            {
                throw new Exception(resObj.GetJSONObject("error").GetString("message"));
            }

            var userObj = resObj.GetJSONObject("result");

            var authUser = new AuthUser
            {
                Uuid = userObj.GetString("userId"),
                Username = userObj.GetString("userName"),
                Nickname = userObj.GetString("userName"),
                Gender = AuthUserGender.Unknown,
                Token = authToken,
                Source = source.GetName(),
                OriginalUser = resObj,
                OriginalUserStr = response
            };
            return authUser;
        }

        public override AuthResponse Refresh(AuthToken oldToken)
        {
            var reqParams = new Dictionary<string, object>
            {
                { "refresh_token", oldToken.RefreshToken },
                { "grant_type", "refresh_token" },
            };

            var reqHeaders = this.getSpecialHeader(this.getRequestId());

            var response = HttpUtils.RequestFormPost(source.AccessToken(), reqParams.SpellParams(), reqHeaders);
            var accessTokenObject = response.ParseObject();

            this.checkResponse(accessTokenObject);

            var authToken = new AuthToken
            {
                AccessToken = accessTokenObject.GetString("access_token"),
                RefreshToken = accessTokenObject.GetString("refresh_token"),
                ExpireIn = accessTokenObject.GetInt32("expires_in"),
                TokenType = accessTokenObject.GetString("token_type")
            };

            return new AuthResponse(AuthResponseStatus.SUCCESS.GetCode(), AuthResponseStatus.SUCCESS.GetDesc(), authToken);
        }

        public override string Authorize(string state)
        {
            return UrlBuilder.FromBaseUrl(base.Authorize(state))
                .QueryParam("scope", config.Scope.IsNullOrWhiteSpace() ? "all" : config.Scope)
                .Build();
        }

        private string spliceBasicAuthStr()
        {
            string encodeToString = encodeBase64($"{config.ClientId}:{config.ClientSecret}");
            return $"Basic {encodeToString}";
        }

        private Dictionary<string, object> getSpecialHeader(string requestId)
        {
            var headers = new Dictionary<string, object>
            {
                { "Content-Type", "application/x-www-form-urlencoded;charset=UTF-8" },
                { "Accept", "text/xml,text/javascript,text/html" },
                { "Accept-Encoding", "gzip" },
                { "User-Agent", "eleme-openapi-java-sdk"},
                { "x-eleme-requestid", requestId},
                { "Authorization", this.spliceBasicAuthStr()}
            };
            return headers;
        }


        private string getRequestId()
        {
            return (Guid.NewGuid().ToString() + "|" + DateTime.Now.Ticks.ToString()).ToUpper();
        }


        /**
        * 校验请求结果
        *
        * @param response 请求结果
        * @return 如果请求结果正常，则返回Exception
        */
        private void checkResponse(Dictionary<string, object> dic)
        {
            if (dic.ContainsKey("error"))
            {
                throw new Exception($"{dic.GetString("error_description")}");
            }
        }

        ///编码
        public string encodeBase64(string contentStr, string encodeType = "utf-8")
        {
            string encode = "";
            byte[] bytes = Encoding.GetEncoding(encodeType).GetBytes(contentStr);
            try
            {
                encode = Convert.ToBase64String(bytes);
            }
            catch
            {
                encode = contentStr;
            }
            return encode;
        }
        ///解码
        public string decodeBase64(string contentStr, string encodeType = "utf-8")
        {
            string decode = "";
            byte[] bytes = Convert.FromBase64String(contentStr);
            try
            {
                decode = Encoding.GetEncoding(encodeType).GetString(bytes);
            }
            catch
            {
                decode = contentStr;
            }
            return decode;
        }


        /**
         * 生成饿了么请求的Signature
         * <p>
         * 代码copy并修改自：https://coding.net/u/napos_openapi/p/eleme-openapi-java-sdk/git/blob/master/src/main/java/eleme/openapi/sdk/utils/SignatureUtil.java
         *
         * @param appKey     平台应用的授权key
         * @param secret     平台应用的授权密钥
         * @param timestamp  时间戳，单位秒。API服务端允许客户端请求最大时间误差为正负5分钟。
         * @param action     饿了么请求的api方法
         * @param token      用户授权的token
         * @param parameters 加密参数
         * @return Signature
         */
        public string generateElemeSignature(long timestamp, string action, string token)
        {
            Dictionary<string, object> dicList = new Dictionary<string, object>();
            dicList.Add("app_key", config.ClientId);
            dicList.Add("timestamp", timestamp);

            var signStr = dicList.Sort().SpellParams();
            string splice = $"{action}{token}{signStr}{config.ClientSecret}";
            string calculatedSignature = hashMd5String(splice);
            return calculatedSignature;
        }

        /// <summary>
        /// 对字符串进行Md5加密，isUpper为True时返回大写，反之小写
        /// </summary>
        /// <param name="willMd5Str"></param>
        /// <param name="isUpper"></param>
        public static string hashMd5String(string willMd5Str, bool isUpper = true)
        {
            //就是比string往后一直加要好的优化容器
            StringBuilder sb = new StringBuilder();
            using (MD5CryptoServiceProvider md5 = new MD5CryptoServiceProvider())
            {
                //将输入字符串转换为字节数组并计算哈希。
                byte[] data = md5.ComputeHash(Encoding.UTF8.GetBytes(willMd5Str));

                //X为     十六进制 X都是大写 x都为小写
                //2为 每次都是两位数
                //假设有两个数10和26，正常情况十六进制显示0xA、0x1A，这样看起来不整齐，为了好看，可以指定"X2"，这样显示出来就是：0x0A、0x1A。 
                //遍历哈希数据的每个字节
                //并将每个字符串格式化为十六进制字符串。
                int length = data.Length;
                for (int i = 0; i < length; i++)
                    sb.Append(data[i].ToString("X2"));

            }
            if (isUpper)
            {
                return sb.ToString().ToUpper();
            }
            else
            {
                return sb.ToString().ToLower();
            }
        }
    }
}