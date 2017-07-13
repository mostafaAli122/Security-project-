using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Security.Cryptography;
using System.Threading.Tasks;

namespace SecurityLibrary.MD5
{
    public class MD5
    {
        public string GetHash(string text)
        {
            //I use md5 class I know it not suppose to do this cause i not undersstand it will 
            System.Security.Cryptography.MD5 md5 = new MD5CryptoServiceProvider();
            byte[] myhash = md5.ComputeHash(Encoding.ASCII.GetBytes(text));
            //convert each byte to hexdecimal 
            StringBuilder stringBuilder = new StringBuilder();
            foreach (byte b in myhash)
            {
                stringBuilder.AppendFormat("{0:x2}", b);
            }
            return stringBuilder.ToString();
        }
    }
}
