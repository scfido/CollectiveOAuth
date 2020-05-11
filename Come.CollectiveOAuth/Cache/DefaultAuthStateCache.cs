﻿using System;

namespace Come.CollectiveOAuth.Cache
{
    public class DefaultAuthStateCache : IAuthStateCache
    {
        /// <summary>
        /// 默认缓存前缀
        /// </summary>
        private static string Default_Cache_Prefix = "CollectiveOAuth_Status_";

        public void Cache(string key, string value)
        {
            HttpRuntimeCache.Set($"{Default_Cache_Prefix}{key}", value);
        }

        public void Cache(string key, string value, long timeout)
        {
            HttpRuntimeCache.Set($"{Default_Cache_Prefix}{key}", value, timeout);
        }

        public bool ContainsKey(string key)
        {
            var cacheObj = HttpRuntimeCache.Get($"{Default_Cache_Prefix}{key}");
            if (cacheObj != null)
            {
                return true;
            }

            return false;
        }

        public string Get(string key)
        {
            var cacheObj = HttpRuntimeCache.Get($"{Default_Cache_Prefix}{key}");
            if (cacheObj != null)
            {
                return Convert.ToString(cacheObj);
            }
            else
            {
                return null;
            }
        }
    }
}