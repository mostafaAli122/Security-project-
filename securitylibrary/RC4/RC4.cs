using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary.RC4
{
    /// <summary>
    /// If the string starts with 0x.... then it's Hexadecimal not string
    /// </summary>
    public class RC4 : CryptographicTechnique
    {
        int[] s = new int[256];
        int[] t = new int[256];
        public override string Decrypt(string cipherText, string key)
        {
            string orignal_cipherText = cipherText;
            //check if the plaintext and key in hex format convert it to string to encrypt it
            if (cipherText.Substring(0, 2) == "0x")
            {
                StringBuilder sb = new StringBuilder();
                for (int i = 2; i < cipherText.Length; i += 2)
                {
                    string hs = cipherText.Substring(i, 2);
                    sb.Append(Convert.ToChar(Convert.ToUInt32(hs, 16)));
                }
                cipherText = sb.ToString();
                sb = new StringBuilder();
                for (int i = 2; i < key.Length; i += 2)
                {
                    string hs = key.Substring(i, 2);
                    sb.Append(Convert.ToChar(Convert.ToUInt32(hs, 16)));
                }
                key = sb.ToString();
            }
            //key Stream 
            int[] K = new int[cipherText.Length];
            for (int i = 0; i < 256; i++)
            {
                s[i] = i;
            }
            int keyLengthCounter = 0;
            //fill T with key 
            for (int i = 0; i < 256; i++)
            {
                if (keyLengthCounter == key.Length)
                    keyLengthCounter = 0;
                t[i] = key[keyLengthCounter];
                keyLengthCounter++;

            }
            int j = 0;
            //Initial permutation of S
            for (int i = 0; i < 256; i++)
            {
                j = (j + s[i] + t[i]) % 256;
                swap(i, j);
            }

            //Generation of key Stream  K
            int I = 0, J = 0;
            int counter = 0;
            while (counter != cipherText.Length)
            {
                I = (I + 1) % 256;
                J = (J + s[I]) % 256;
                swap(I, J);
                int ind = (s[I] + s[J]) % 256;
                K[counter] = s[ind];
                counter++;
            }
            //decrypt(xor ciphertext with K (key stream))
            StringBuilder PlainText = new StringBuilder();
            for (int i = 0; i < cipherText.Length; i++)
            {
                PlainText.Append((char)(cipherText[i] ^ K[i]));
            }
            //convert the decrypted string to Hex and append "0x" in first
            if (orignal_cipherText.Substring(0, 2) == "0x")
            {
                string ciphertextHex = StringToHex(PlainText.ToString());
                return ciphertextHex.Insert(0, "0x");
            }
            return PlainText.ToString();
        }

        public override  string Encrypt(string plainText, string key)
        {
            string orignal_plainText = plainText;
            //check if the plaintext and key in hex format convert it to string to encrypt it
            if (plainText.Substring(0, 2) == "0x")
            {
                StringBuilder sb = new StringBuilder();
                for (int i = 2; i < plainText.Length; i += 2)
                {
                    string hs = plainText.Substring(i, 2);
                    sb.Append(Convert.ToChar(Convert.ToUInt32(hs, 16)));
                }
                plainText = sb.ToString();
                sb = new StringBuilder();
                for (int i = 2; i < key.Length; i += 2)
                {
                    string hs = key.Substring(i, 2);
                    sb.Append(Convert.ToChar(Convert.ToUInt32(hs, 16)));
                }
                key = sb.ToString();
            }

            //key Stream 
            int[] K = new int[plainText.Length];
            for (int i = 0; i < 256; i++)
            {
                s[i] = i;
            }
            int keyLengthCounter = 0;
            //fill T with key 
            for (int i = 0; i < 256; i++)
            {
                if (keyLengthCounter == key.Length)
                    keyLengthCounter = 0;
                t[i] = key[keyLengthCounter];
                keyLengthCounter++;
                
            }
            int j = 0;
            //Initial permutation of S
            for (int i = 0; i < 256; i++)
            {
                j = (j + s[i] + t[i])%256;
                swap(i, j);
            }

            //Generation of key Stream  K
             int I = 0 , J=0 ;
            int counter = 0;
            while (counter!=plainText.Length)
            {
                I = (I + 1)%256;
                J = (J + s[I]) % 256;
                swap(I, J);
                int ind = (s[I] + s[J]) % 256;
                K[counter] = s[ind];
                counter++;
            }
            //encrypt(xor plaintext with K (key stream))
            StringBuilder cipherText = new StringBuilder();
            
            for (int i = 0; i < plainText.Length; i++)
            {
                cipherText.Append((char)(plainText[i] ^ K[i]));
            }
            //convert the encrypted string to Hex and append "0x" in first
            if (orignal_plainText.Substring(0, 2) == "0x")
            {
                string ciphertextHex = StringToHex(cipherText.ToString());
                 return ciphertextHex.Insert(0, "0x");
            }

            return cipherText.ToString();
        }
        public void swap(int i, int j)
        {
            int tmp = s[i];
            s[i] = s[j];
            s[j] = tmp;
        }
        //func to convert string to hex
        private string StringToHex(string hexstring)
        {
            StringBuilder sb = new StringBuilder();
            foreach (char t in hexstring)
            {
                //Note: X for upper, x for lower case letters
                sb.Append(Convert.ToInt32(t).ToString("x"));
            }
            return sb.ToString();
        }
    }
}
