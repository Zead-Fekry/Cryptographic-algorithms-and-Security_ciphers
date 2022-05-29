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
            char[] alphabet = { 'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z' }; //all the alphapet
            char[] mykey = { '-', '-', '-', '-', '-', '-', '-', '-', '-', '-', '-', '-', '-', '-', '-', '-', '-', '-', '-', '-', '-', '-', '-', '-', '-', '-' };
            cipherText= cipherText.ToLower();
            plainText = plainText.ToLower();                    

            for (int i = 0; i < plainText.Length; i++)
            {
                for (int j = 0; j < alphabet.Length; j++)
                {
                    if (plainText[i].Equals(alphabet[j]))
                    {
                        mykey[j] = cipherText[i];


                    }
                }
            }
            for (int i = 0; i < cipherText.Length; i++)
            {
                for (int j = 0; j < alphabet.Length; j++)
                {
                    if (cipherText[i].Equals(alphabet[j]))
                    {
                        alphabet[j] = '/';


                    }
                }
            }

            for (int i = 0; i < alphabet.Length; i++)
            {
                for (int j = 0; j < mykey.Length; j++)
                {
                    if (alphabet[i] != '/' & mykey[j] == '-')
                    {
                        mykey[j] = alphabet[i];
                        break;
                    }
                }
            }



            String KEY = new string(mykey);



            return KEY;
        }

        public string Decrypt(string cipherText, string key)
        {
            string alphabet = "abcdefghijklmnopqrstuvwxyz";
            cipherText= cipherText.ToLower();
            key= key.ToLower();
            int lenght = cipherText.Length;
            char [] plain  = new char[lenght];
            for (int i = 0; i < lenght; i++)
            {
                for (int j = 0; j < alphabet.Length; j++)
                {
                    if (cipherText[i] == key[j])
                    {
                        plain[i] = alphabet[j];
                    }
                }
            }
            String plaintext = new string(plain);

            return plaintext;
        }

        public string Encrypt(string plainText, string key)
        {
            string alphabet = "abcdefghijklmnopqrstuvwxyz";
            plainText = plainText.ToLower();
            key = key.ToLower();
            int  lenght = plainText.Length;
            char[] cipher = new Char[lenght];
            for (int i = 0; i < lenght; i++)
            {
                for (int j = 0; j < alphabet.Length; j++)
                {
                    if (plainText[i] == alphabet[j])
                    {
                        cipher[i] = key[j];
                    }        
                }
            }


            string cipher1 = new string(cipher);
           
            return cipher1;
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
            string Freq = "ETAOINSRHLDCUMFPGWYBVKXJQZ".ToLower();

            Dictionary<char,int>  alphabet = new Dictionary<char, int>();
            cipher = cipher.ToLower();
            int lenght = cipher.Length;
            StringBuilder builder = new StringBuilder();
            
            char[] plaintext = new char[lenght];
            for (int i = 0;i < cipher.Length; i++)
            {
                if (alphabet.ContainsKey(cipher[i]))
                    alphabet[cipher[i]]++;
                else
                    alphabet.Add(cipher[i], 1);
            }
            Dictionary<char, int> OrderdAlphabet = alphabet.OrderBy(x=>x.Value).Reverse().ToDictionary(x=>x.Key,x=>x.Value);
           
            builder.Append(cipher.ToUpper());
            for( int i =0; i< OrderdAlphabet.Count; i++)
            {
                char mostOccur = OrderdAlphabet.ElementAt(i).Key;
                builder.Replace(Char.ToUpper(mostOccur), Freq[i]);

            }
            return builder.ToString();
        }
    }
}
