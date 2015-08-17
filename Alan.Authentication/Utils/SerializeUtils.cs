using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Web.Script.Serialization;

namespace Alan.Authentication.Utils
{
    /// <summary>
    /// 序列化实用类
    /// </summary>
    public static class SerializeUtils
    {
        public static string ToJson(this object data)
        {
            JavaScriptSerializer serializer = new JavaScriptSerializer();
            return serializer.Serialize(data);
        }
        public static T ParseJson<T>(this string json)
        {
            if (String.IsNullOrWhiteSpace(json)) return default(T);
            JavaScriptSerializer serializer = new JavaScriptSerializer();
            return serializer.Deserialize<T>(json);
        }
    }
}
