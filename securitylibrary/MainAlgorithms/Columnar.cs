using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    public class Columnar : ICryptographicTechnique<string, List<int>>
    {
        public List<int> Analyse(string plainText, string cipherText)
        {
            int rownum = 0;
            int keycount = 0;
            int counter = 0;
            cipherText = cipherText.ToLower();
            int check = 0;

            for (int i = 4; i <8 ; i++)
            {
                if (plainText.Length % i == 0)
                {
                    keycount = i;
                }
            }
            rownum = plainText.Length / keycount;
            char[,] metrix1 = new char[rownum, keycount];
            char[,] metrix2 = new char[rownum, keycount];
            List<int> key = new List<int>(keycount);


            for (int i = 0; i < rownum; i++)
            {
                for (int j = 0; j < keycount; j++)
                {
                    if (counter < plainText.Length)
                        metrix1[i, j] = plainText[counter];
                    if (counter >= plainText.Length)
                    {
                        if (metrix1.Length > plainText.Length)
                            metrix1[i, j] = 'x';
                    }
                    counter++;
                }
            }

            counter = 0;
            for (int i = 0; i < keycount; i++)
            {
                for (int j = 0; j < rownum; j++)
                {
                    if (counter == plainText.Length)
                        break;
                    metrix2[j, i] = cipherText[counter];
                    counter++;
                }
            }

            for (int i = 0; i < keycount; i++)
            {
                for (int k = 0; k < keycount; k++)
                {
                    for (int j = 0; j < rownum; j++)
                    {
                        if (metrix1[j, i] == metrix2[j, k])
                        {
                            check++;
                        }
                        if (check == rownum)
                            key.Add(k + 1);
                    }
                    check = 0;
                }
            }
            if (key.Count == 0)
            {
                for (int i = 0; i < keycount+2; i++)
                {
                    key.Add(0);
                }
            }
            return key;
        }

        public string Decrypt(string cipherText, List<int> key)
        {
            cipherText = cipherText.ToLower();
            int rownum = (int)Math.Ceiling((decimal)cipherText.Length / key.Count);
            char[,] metrix = new char[rownum, key.Count];
            char[,] swapedMetrix = new char[rownum, key.Count];
            int counter = 0;
            string plaintext = "";
            int numofcellX = metrix.Length - cipherText.Length;
            int numofcellXo_cunter = 0;
            for (int i = 0; i < key.Count; i++)
            {
                for (int j = 0; j < rownum; j++)
                {
                    if (counter == cipherText.Length)
                        break;
                    metrix[j, i] = cipherText[counter];
                    counter++;
                    if (numofcellXo_cunter != numofcellX && j == rownum - 1 && i >= (key.Count - numofcellX))
                    {
                        metrix[j, i] = ' ';
                        numofcellXo_cunter++;
                        counter--;
                    }
                }
            }

            for (int i = 0; i < key.Count; i++)
            {
                for (int j = 0; j < rownum; j++)
                {
                    swapedMetrix[j, key.IndexOf(i+1)] = metrix[j, i];
                }
            }
            for (int i = 0; i < rownum; i++)
            {
                for (int j = 0; j < key.Count; j++)
                {
                    plaintext += swapedMetrix[i, j];
                }
            }
            plaintext = plaintext.Replace(" ", "");
            return plaintext.ToLower();
        }

        public string Encrypt(string plainText, List<int> key)
        {
            int rownum = (int)Math.Ceiling((decimal)plainText.Length / key.Count);
            char[,] metrix = new char[rownum, key.Count];
            char[,] swapedMetrix = new char[rownum, key.Count];
            int counter = 0;
            string ciphertext="";

            for (int i = 0; i < rownum; i++)
            {
                for (int j = 0; j < key.Count; j++)
                {
                    if(counter<plainText.Length)
                        metrix[i, j] = plainText[counter];
                    if (counter >= plainText.Length)
                    {
                       if(metrix.Length>plainText.Length)
                              metrix[i, j] = 'x';
                    }
                    counter++;
                }
            }

            for (int i = 0; i < key.Count; i++)
            {
                for (int j = 0; j < rownum; j++)
                {
                    swapedMetrix[j, key[i]-1] = metrix[j, i];
                }
            }
            for (int i = 0; i < key.Count; i++)
            {
                for (int j = 0; j < rownum; j++)
                {
                    ciphertext+= swapedMetrix[j, i];
                }
            }
            return ciphertext.ToLower();
        }
    }
}
