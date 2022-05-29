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
            cipherText = cipherText.ToLower();
            plainText = plainText.ToLower();
            for(int i=1; i<plainText.Length; i++)
            {
                if (cipherText.Equals(Encrypt(plainText, i))) 
                return i;
            }
            return 0;
        }

        public string Decrypt(string cipherText, int key)
        {

            int length = (int)Math.Floor((double)cipherText.Length / key);
            int mod = cipherText.Length%key;
            List<string> t = new List<string>();
            int ptr = 0;
            for (int i = 0; i < key; i++)
            {
                if (i >= mod)
                {
                    t.Add(cipherText.Substring(ptr, length));
                    ptr += length;
                }
                else
                {
                    t.Add(cipherText.Substring(ptr, length + 1));
                    ptr += length + 1;
                }
            }
            StringBuilder pn = new StringBuilder();
            for(int i =0; i<=length; i++)
            {
              foreach (string s in t)
                {
                    if(s.Length>i)
                        pn.Append(s[i]);
                    
                }
            }


            return pn.ToString() ;
        }

        public string Encrypt(string plainText, int key)
        {
             
            List<StringBuilder> t = new List<StringBuilder>();

            for (int i = 0; i < key; i++)
            {
                t.Add(new StringBuilder());
            }
            for (int i=0; i<plainText.Length; i++)
            {
                t[i % key].Append(plainText[i]);
            }

            StringBuilder d1 = new StringBuilder();
            t.ForEach(d => d1.Append(d));   
 

            return d1.ToString();
        }
    }
}
