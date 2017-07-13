using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    public class Ceaser : ICryptographicTechnique<string, int>
    {

        public string Encrypt(string plainText, int key)
        {
            string encode = "";
            for (int i = 0; i < plainText.Length; i++)
            {
                if (plainText[i] + key > 122)
                    encode += (char)(96 + (plainText[i] + key) % 122);
                else
                    encode += (char)(plainText[i] + key);
            }
            return encode;
        }

        public string Decrypt(string cipherText, int key)
        {
            string cipherTextlower = cipherText.ToLower();
            string decode = "";
            for (int i = 0; i < cipherText.Length; i++)
            {
                if (cipherTextlower[i] - key < 97)
                    decode += (char)(122 - (96-(cipherTextlower[i] - key)));
                else
                    decode += (char)(cipherTextlower[i] - key);
            }
            return decode;
        }

        public int Analyse(string plainText, string cipherText)
        {
            int key;
            string cipherTextlower = cipherText.ToLower();
            if (plainText[1] > cipherTextlower[1] )
                key = cipherTextlower[1]- plainText[1] + 26 ;

            else
                key = cipherTextlower[1] - plainText[1];

            return key;
        }
    }
}
