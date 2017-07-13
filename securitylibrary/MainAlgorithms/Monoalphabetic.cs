using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    public class Monoalphabetic : ICryptographicTechnique<string, string>
    {
        public string Analyse(string plainText, string cipherText)
        {
            int k = 0;
            string alphapet = "abcdefghijklmnopqrstuvwxyz";
            StringBuilder str = new StringBuilder();
            string plainTextlower = plainText.ToLower();
            string ciphertextlower = cipherText.ToLower();

            //let's assume pt=c & ct=e so c(99)-97=2 next put in key index of 2 char from ct(e)
            char[] key = new char[26];
            for (int i = 0; i < plainTextlower.Length; i++)
            {
                int j = plainTextlower[i] - 97;
                key[j] = ciphertextlower[i];
            }
            //append chars that not contains in key into string builder (str) 
            for (int i = 0; i < 26; i++)
            {
                if (!key.Contains(alphapet[i]))
                    str.Append(alphapet[i]);
            }
            //then fill empty places in key with thos chars in str
            for (int i = 0; i < key.Length-1; i++)
            {
                if (key[i] == '\0')
                {
                    key[i] = str[k];
                    k++;
                }
            }
            return new string(key);
        }

        public string Decrypt(string cipherText, string key)
        {
            string ciphertextlower = cipherText.ToLower();
            char[] chars = new char[ciphertextlower.Length];
            for (int i = 0; i < ciphertextlower.Length; i++)
            {
                if (ciphertextlower[i] == ' ')
                {
                    chars[i] = ' ';
                }
                else
                {
                    int j = key.IndexOf(ciphertextlower[i]) + 97;
                    chars[i] = (char)j;
                }
            }
            return new string(chars);
        }

        public string Encrypt(string plainText, string key)
        {
            char[] chars = new char[plainText.Length];
            for (int i = 0; i < plainText.Length; i++)
            {
                if (plainText[i] == ' ')
                {
                    chars[i] = ' ';
                }

                else
                {
                    int j = plainText[i] - 97;
                    chars[i] = key[j];
                }
            }

            return new string(chars);
        }

        /// <summary>
        /// Frequency Information:
        /// E   12.51%
        /// T	9.25
        /// A	8.04
        /// O	7.60
        /// I	7.26
        /// N	7.09
        /// S	6.54
        /// R	6.12
        /// H	5.49
        /// L	4.14
        /// D	3.99
        /// C	3.06
        /// U	2.71
        /// M	2.53
        /// F	2.30
        /// P	2.00
        /// G	1.96
        /// W	1.92
        /// Y	1.73
        /// B	1.54
        /// V	0.99
        /// K	0.67
        /// X	0.19
        /// J	0.16
        /// Q	0.11
        /// Z	0.09
        /// </summary>
        /// <param name="cipher"></param>
        /// <returns>Plain text</returns>
        public string AnalyseUsingCharFrequency(string cipher)
        {
            int counter = 0;
            char[] plain = new char[cipher.Length];

            string alphapet = "abcdefghijklmnopqrstuvwxyz";
            string frequencychar = "etaoinsrlhdcmpufgwybvkjxqz";
            int[] frequency = new int[26];
            string cipherlower = cipher.ToLower();

            for (int i = 0; i < 26; i++)
            {
                frequency[i] = 0;
            }
            //count the freq of each char in alphapet occur in cipher text and put the result in freqency int arr
            for (int i = 0; i < alphapet.Length; i++)
            {
                for (int j = 0; j < cipherlower.Length; j++)
                {
                    if (alphapet[i] == cipherlower[j])
                        frequency[i]++;
                }

            }
            //put each alphapet char (key) and it's freq(value) in cipher in dictionary 
            var dictionary = new Dictionary<string, int>();
            for (int i = 0; i < 26; i++)
            {
                dictionary.Add(alphapet[i].ToString(), frequency[i]);
            }
            //rearrang nodes in dictionary descending put the result in list
            List<KeyValuePair<string, int>> list = (from kv in dictionary orderby kv.Value descending select kv).ToList();

            // Loop through keys.
            int ind = 0;
            foreach (KeyValuePair<string, int> pair in list)
            {
                char itemfreq = frequencychar[ind];
                string newtxt = "";
                //substitute each char in cipher by it's corressponding char in dectionary 
                for (int i = 0; i < cipherlower.Length; i++)
                {
                    if (pair.Key == cipherlower[i].ToString())
                    {
                        newtxt = cipherlower.Remove(i, 1);
                        cipherlower = newtxt;
                        newtxt = cipherlower.Insert(i, " ");
                        cipherlower = newtxt;
                        plain[i] = itemfreq;
                        counter++;
                    }
                    if (counter == pair.Value)
                        break;
                }

                counter = 0;
                ind++;

            }

            return new string (plain);
        }
       
    }
}
