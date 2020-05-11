using System;

namespace Come.CollectiveOAuth.Utils
{
    public class AuthStateUtils
    {
        /// <summary>
        /// 生成随机state
        /// </summary>
        /// <returns></returns>
        public static string CreateState()
        {
            return Guid.NewGuid().ToString();
        }
    }
}