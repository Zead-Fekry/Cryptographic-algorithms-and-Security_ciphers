using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary.AES
{
    public class ExtendedEuclid 
    {
        /// <summary>
        /// 
        /// </summary>
        /// <param name="number"></param>
        /// <param name="baseN"></param>
        /// <returns>Mul inverse, -1 if no inv</returns>
        public int GetMultiplicativeInverse(int number, int baseN)
        {
            int []  taple = new int[7];
            taple[0] = 0;
            taple[1] = 1;
            taple[2] = 0;
            taple[3] = baseN;
            taple[4] = 0;
            taple[5] = 1;
            taple[6] = number;
            do
            {
                int cont = taple[1];
                int cont2 = taple[2];
                int rem1 = taple[4];
                int rem2 = taple[5];
                if (taple[6] == 0)
                {
                    return -1;
                }
                int rev = taple[6];
                taple[0] = taple[3] / taple[6];
                taple[6] = taple[3] % taple[6];
                taple[1] = taple[4];
                taple[2] = taple[5];
                taple[3] = rev;
                taple[4] = cont - (rem1 * taple[0]);
                taple[5] = cont2 - (rem2 * taple[0]);



            } while (!(taple[6] == 1));
           
            if (taple[5] < 0)
            {
                
                int d = taple[5]/baseN;
                
                int result = (taple[5]) - (-(++d) * baseN);
                return result;
            }
            return taple[5]%baseN;
        }
    }
}
