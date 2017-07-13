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
            int b0 = baseN, tmp, q;
            int Myx0 = 0, Myx1 = 1;
            if (baseN == 1) return 1;
            while (number > 1)
            {
                if (baseN == 0)
                    return -1;
                q = number / baseN;
                tmp = baseN;
                baseN = number % baseN;
                number = tmp;
                tmp = Myx0;
                Myx0 = Myx1 - q * Myx0;
                Myx1 = tmp;
            }
            if (Myx1 < 0) Myx1 += b0;
            return Myx1;
        }
    }
}
