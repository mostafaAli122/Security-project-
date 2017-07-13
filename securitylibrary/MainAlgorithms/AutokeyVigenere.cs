using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    public class AutokeyVigenere : ICryptographicTechnique<string, string>
    {
        public string Analyse(string plainText, string cipherText)
        {
            cipherText = cipherText.ToLower();
            char[,] Metrix = generatingvingnereMetrix();
            string key = "";
            string actualKey = "";
            string addedstring = "";
            for (int i = 0; i < plainText.Length; i++)
            {
                int[] index = searchIndex_analyses(plainText[i], cipherText[i]);
                key += Metrix[index[0], 0];
            }

            for (int i = 0; i < key.Length; i++)
            {
                if (key[i] == plainText[0])
                {
                   addedstring= key.Substring(i);
                    if (addedstring == plainText.Substring(0, addedstring.Length))
                        actualKey = key.Substring(0, key.Length - addedstring.Length);
                }
            }
            return actualKey;
        }

        public string Decrypt(string cipherText, string key)
        {
            cipherText = cipherText.ToLower();
            char[,] Metrix = generatingvingnereMetrix();
            string plaintext = "";
            int keylen = key.Length;
            
            for (int i = 0; i < cipherText.Length; i++)
            {
                int[] index = searchIndex_Decrypt(key[i], cipherText[i]);
                plaintext += Metrix[0, index[1]];

                if (key.Length != cipherText.Length)
                   key = key.Insert(key.Length, plaintext[i].ToString());
            }
            return plaintext;
        }

        public string Encrypt(string plainText, string key)
        {
            char[,] Metrix = generatingvingnereMetrix();
            string cipherText = "";
            int keylen = key.Length;
            if (key.Length!=plainText.Length)
            {
                for (int i = 0; i < plainText.Length-keylen; i++)
                {
                    key = key.Insert(key.Length, plainText[i].ToString());
                }
            }
            for (int i = 0; i < plainText.Length; i++)
            {
                int[] index = searchIndex(key[i], plainText[i]); 
                cipherText += Metrix[index[0],index[1]];
            }

            return cipherText.ToUpper();
        }
        //generatingvingnereMetrix
        public char[,] generatingvingnereMetrix()
        {
            char[,] Metrix = new char[26, 26];
            string alpabet= "abcdefghijklmnopqrstuvwxyz";
            for (int row = 0; row < 26; row++)
            {
                for (int col = 0; col < 26; col++)
                {
                    Metrix[row, col] = alpabet[col];
                }
                alpabet = alpabet.Insert(alpabet.Length, alpabet[0].ToString());
                alpabet = alpabet.Remove(0, 1);
            }
            return Metrix;
        }
        //searchIndex
        public int[] searchIndex(char keychar,char plainchar)
        {
            char[,] Metrix = generatingvingnereMetrix();
            int[] index = new int[2];

            for (int i = 0; i < 26; i++)
            {
                if (Metrix[i, 0] == keychar)
                {
                    index[0] = i;
                    break;
                }
            }
            for (int i = 0; i < 26; i++)
            {
                if (Metrix[0, i] == plainchar)
                {
                    index[1] = i;
                    break;
                }
            }
            return index;
        }
        //searchIndex_Decrypt
        public int[] searchIndex_Decrypt(char keychar, char cipherchar)
        {
            char[,] Metrix = generatingvingnereMetrix();
            int[] index = new int[2];

            for (int i = 0; i < 26; i++)
            {
                if (Metrix[i, 0] == keychar)
                {
                    index[0] = i;
                    break;
                }
            }
            for (int i = 0; i < 26; i++)
            {
                if (Metrix[index[0], i] == cipherchar)
                {
                    index[1] = i;
                    break;
                }
            }
            return index;
        }
        //searchIndex_analyses
        public int[] searchIndex_analyses(char plaintextchar, char cipherchar)
        {
            char[,] Metrix = generatingvingnereMetrix();
            int[] index = new int[2];

            for (int i = 0; i < 26; i++)
            {
                if (Metrix[0, i] == plaintextchar)
                {
                    index[1] = i;
                    break;
                }
            }
            for (int i = 0; i < 26; i++)
            {
                if (Metrix[i, index[1]] == cipherchar)
                {
                    index[0] = i;
                    break;
                }
            }
            return index;
        }

    }
}
