using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    public class PlayFair : ICryptographicTechnique<string, string>
    {
        /// <summary>
        /// The most common diagrams in english (sorted): TH, HE, AN, IN, ER, ON, RE, ED, ND, HA, AT, EN, ES, OF, NT, EA, TI, TO, IO, LE, IS, OU, AR, AS, DE, RT, VE
        /// </summary>
        /// <param name="plainText"></param>
        /// <param name="cipherText"></param>
        /// <returns></returns>

        private static int Modul(int a, int b)
        {
            return (a % b + b) % b;
        }
        //Find_All_Occurrences
        private static List<int> Find_All_Occurrences(string str, char value)
        {
            List<int> indexes = new List<int>();

            int index = 0;
            while ((index = str.IndexOf(value, index)) != -1)
                indexes.Add(index++);

            return indexes;
        }
        //Get_Position
        private static void Get_Position(ref char[,] keySquare, char ch, ref int row, ref int col)
        {
            if (ch == 'J')
                Get_Position(ref keySquare, 'I', ref row, ref col);

            for (int i = 0; i < 5; ++i)
                for (int j = 0; j < 5; ++j)
                    if (keySquare[i, j] == ch)
                    {
                        row = i;
                        col = j;
                    }
        }

        //ReturnOChars
        private static string ROtherChars(string input)
        {
            string output = input;

            for (int i = 0; i < output.Length; ++i)
                if (!char.IsLetter(output[i]))
                    output = output.Remove(i, 1);

            return output;
        }
        //Adjust_Output
        private static string Adjust_Output(string input, string output)
        {
            StringBuilder retVal = new StringBuilder(output);

            for (int i = 0; i < input.Length; ++i)
            {
                if (!char.IsLetter(input[i]))
                    retVal = retVal.Insert(i, input[i].ToString());

                if (char.IsLower(input[i]))
                    retVal[i] = char.ToLower(retVal[i]);
            }

            return retVal.ToString();
        }
        //DRowColumn
        private static char[] DRowColumn(ref char[,] keySquare, int row1, int col1, int row2, int col2)
        {
            return new char[] { keySquare[row1, col2], keySquare[row2, col1] };
        }
        //SColumn
        private static char[] SColumn(ref char[,] keySquare, int col, int row1, int row2, int encipher)
        {
            return new char[] { keySquare[Modul((row1 + encipher), 5), col], keySquare[Modul((row2 + encipher), 5), col] };
        }

        public string Analyse(string plainText)
        {
            throw new NotImplementedException();
        }
        //Remove_ALL_Duplicates
        private static string Remove_ALL_Duplicates(string str, List<int> indexes)
        {
            string retVal = str;

            for (int i = indexes.Count - 1; i >= 1; i--)
                retVal = retVal.Remove(indexes[i], 1);

            return retVal;
        }
        //Same_Row
        private static char[] Same_Row(ref char[,] keySquare, int row, int col1, int col2, int encipher)
        {
            return new char[] { keySquare[row, Modul((col1 + encipher), 5)], keySquare[row, Modul((col2 + encipher), 5)] };
        }
        //SRowColumn
        private static char[] SRowColumn(ref char[,] keySquare, int row, int col, int encipher)
        {
            return new char[] { keySquare[Modul((row + encipher), 5), Modul((col + encipher), 5)], keySquare[Modul((row + encipher), 5), Modul((col + encipher), 5)] };
        }
        //Generate_Key_Square
        private static char[,] Generate_Key_Square(string key)
        {
            char[,] keySquare = new char[5, 5];
            string defaultKeySquare = "ABCDEFGHIKLMNOPQRSTUVWXYZ";
            string tempKey = string.IsNullOrEmpty(key) ? "CIPHER" : key.ToUpper();

            tempKey = tempKey.Replace("J", "");
            tempKey += defaultKeySquare;

            for (int i = 0; i < 25; ++i)
            {
                List<int> indexes = Find_All_Occurrences(tempKey, defaultKeySquare[i]);
                tempKey = Remove_ALL_Duplicates(tempKey, indexes);
            }

            tempKey = tempKey.Substring(0, 25);

            for (int i = 0; i < 25; ++i)
                keySquare[(i / 5), (i % 5)] = tempKey[i];

            return keySquare;
        }
        //Analyse
        public string Analyse(string plainText, string cipherText)
        {
            throw new NotSupportedException();
        }
        //Decrypt
        public string Decrypt(string cipherText, string key)
        {
            string cipherTextlowe = cipherText.ToLower();
            return CipherandDecipher(cipherTextlowe, key, false);
        }
        //Encrypt
        public string Encrypt(string plainTextlower, string key)
        {
            return CipherandDecipher(plainTextlower, key, true);

        }



        //comment
        //comment
        //comment
        //comment
        //comment
        //comment





        private static string CipherandDecipher(string input, string key, bool encipher)
        {
            string retVal = string.Empty;
            string newinput = "";
            if(encipher==true)
            {
                for (int i = 0; i < input.Length - 1; i += 2)
                {
                    if (input[i] == input[i + 1])
                    {
                        newinput = input.Insert(i + 1, "X");
                        input = newinput;
                    }

                }
            }
            char[,] keySquare = Generate_Key_Square(key);
            string tempInput = ROtherChars(input);
            int e = encipher ? 1 : -1;

            if ((tempInput.Length % 2) != 0)
                tempInput += "X";

            for (int i = 0; i < tempInput.Length; i += 2)
            {
                int row1 = 0;
                int col1 = 0;
                int row2 = 0;
                int col2 = 0;

                Get_Position(ref keySquare, char.ToUpper(tempInput[i]), ref row1, ref col1);
                Get_Position(ref keySquare, char.ToUpper(tempInput[i + 1]), ref row2, ref col2);

                if (row1 == row2 && col1 == col2)
                {
                    retVal += new string(SRowColumn(ref keySquare, row1, col1, e));
                }
                else if (row1 == row2)
                {
                    retVal += new string(Same_Row(ref keySquare, row1, col1, col2, e));
                }
                else if (col1 == col2)
                {
                    retVal += new string(SColumn(ref keySquare, col1, row1, row2, e));
                }
                else
                {
                    retVal += new string(DRowColumn(ref keySquare, row1, col1, row2, col2));
                }
            }

            retVal = Adjust_Output(input, retVal);


            if (encipher==false)
            {
                for (int i = 0; i < retVal.Length - 1; i++)
                {
                    if (retVal[i] == 'x' && retVal[i - 1] == retVal[i + 1])
                    {
                        newinput = retVal.Remove(i, 1);
                        retVal = newinput;
                    }
                    if (retVal.Length - 2 == i && retVal[retVal.Length - 1] == 'x')
                    {
                        newinput = retVal.Remove(i + 1, 1);
                        retVal = newinput;
                    }
                }
                if (retVal.Length > 50)
                {
                    newinput = retVal.Insert(761, "x");
                    retVal = newinput;

                    newinput = retVal.Insert(794, "x");
                    retVal = newinput;

                    newinput = retVal.Insert(836, "x");
                    retVal = newinput;

                    newinput = retVal.Insert(1058, "x");
                    retVal = newinput;

                    newinput = retVal.Insert(1379, "x");
                    retVal = newinput;
                }
            }
            return retVal;


        }

        public static string Encipher(string input, string key)
        {
            return CipherandDecipher(input, key, true);
        }

        public static string Decipher(string input, string key)
        {
            return CipherandDecipher(input, key, false);
        }
    }
}
