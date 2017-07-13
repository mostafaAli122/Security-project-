using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    public class RailFence : ICryptographicTechnique<string, int>
    {
        public int Analyse(string plainText, string cipherText)
        {
            /*ex: plaintext=  meetmeaftertheparty
                  ciphertext= mtaehayemfrereettpt
                  key=2
                  m=m remove e from plaintext
                  e!=t remove e from plaintext & key =3 
                  m==m && t==t break then returned key =3
            */
            cipherText = cipherText.ToLower();
            int key=2;
            for (int i = 0; i < plainText.Length/2; i++)
            {
                if (plainText[i] != cipherText[i])
                {
                    plainText = plainText.Remove(i, 1);
                    key++;
                }
                if(plainText[i] == cipherText[i])
                    plainText = plainText.Remove(i + 1, 1);
                if (plainText[0] == cipherText[0] && plainText[1] == cipherText[1])
                    break;
            }
            return key;
        }

        public string Decrypt(string cipherText, int key)
        {
            int colnum = (int)Math.Ceiling((decimal)cipherText.Length / key);
            char[,] metrix = new char[key, colnum];
            int counter = 0;
            string plainText = "";
            int num_ofChar_inLastCol = cipherText.Length % key;
            int Numinsert = 0;
            for (int i = 0; i < key; i++)
            {
                for (int j = 0; j < colnum; j++)
                {
                    if (counter == cipherText.Length)
                        break;
                    if (Numinsert != num_ofChar_inLastCol && j == colnum - 1)
                    {
                        metrix[i, colnum - 1] = cipherText[counter];
                        Numinsert++;
                    }
                    else if (Numinsert == num_ofChar_inLastCol && j == colnum - 1)
                        metrix[i, colnum - 1] = '\0';
                    metrix[i, j] = cipherText[counter];
                    counter++;
                }
            }
            for (int i = 0; i < colnum; i++)
            {
                for (int j = 0; j < key; j++)
                {
                    plainText += metrix[j, i];
                }
            }
            plainText = plainText.Replace("\0", "").ToLower();
            return plainText;
        }

        public string Encrypt(string plainText, int key)
        {
            int colnum = (int)Math.Ceiling((decimal)plainText.Length / key);
            char[,] metrix = new char[key, colnum];
            int counter = 0;
            string cipherText = "";
            for (int i = 0; i < colnum; i++)
            {
                for (int j = 0; j < key; j++)
                {
                    if (counter==plainText.Length)
                         break;
                    metrix[j, i] = plainText[counter];
                    counter++;
                }
            }
            for (int i = 0; i < key; i++)
            {
                for (int j = 0; j < colnum; j++)
                {
                    cipherText+= metrix[i, j] ;
                }
            }
            cipherText = cipherText.Replace("\0","");
            return cipherText;
        }
    }
}
