using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
namespace SecurityLibrary.RSA
{
    public class RSA
    {
        public int Encrypt(int p, int q, int M, int e)
        {

            Int64 n = p * q;
            Int64 c = 1;
            Int64 NM = 1;
            for (int j = 0; j < e; j++)
            {
                NM = (NM * M) % n;
            }
            c = NM % n;
            return Convert.ToInt32(c % n);



        }

        public int Decrypt(int p, int q, int C, int e)
        {
            Int64 n = p * q;
            int phiOFn = eulerTotient((int)n);
            //d=e^-1 mod phi(n)
            int d = GetMultiplicativeInverse(e, phiOFn);
            Int64 NM = 1,M=1;
            //M=C^d mod e
            for (int j = 0; j < d; j++)
            {
                NM = (NM * C) % n;
            }
            M = NM % n;
            return Convert.ToInt32(M % n);

        }
        //get multiplicative inverse 
        int GetMultiplicativeInverse(int number, int baseN)
        {
            int b0 = baseN, tmp1, q;
            int x0 = 0, x1 = 1;
            if (baseN == 1) return 1;
            while (number > 1)
            {
                if (baseN == 0)
                    return -1;
                q = number / baseN;
                tmp1 = baseN;
                baseN = number % baseN;
                number = tmp1;
                tmp1 = x0;
                x0 = x1 - q * x0;
                x1 = tmp1;
            }
            if (x1 < 0) x1 += b0;
            return x1;
        }
        //get sieve primes
        bool[] GetPrimeSieve(long upTo)
        {
            long sieveSize = upTo + 1;
            bool[] sieve = new bool[sieveSize];
            Array.Clear(sieve, 0, (int)sieveSize);
            sieve[0] = true;
            sieve[1] = true;
            long p, max = (long)Math.Sqrt(sieveSize) + 1;
            for (long i = 2; i <= max; i++)
            {
                if (sieve[i]) continue;
                p = i + i;
                while (p < sieveSize) { sieve[p] = true; p += i; }
            }
            return sieve;
        }

        long[] GetPrimesUpTo(long upTo)
        {
            if (upTo < 2) return null;
            bool[] sieve = GetPrimeSieve(upTo);
            long[] primes = new long[upTo + 1];

            long index = 0;
            for (long i = 2; i <= upTo; i++) if (!sieve[i]) primes[index++] = i;

            Array.Resize(ref primes, (int)index);
            return primes;
        }
        //euler totient function phi(n)
        int eulerTotient(int n)
        {
            long[] primes = GetPrimesUpTo(n + 1);    //this can be precalculated beforehand
            int numPrimes = primes.Length;

            int totient = n;
            int currentNum = n, temp, p, prevP = 0;
            for (int i = 0; i < numPrimes; i++)
            {
                p = (int)primes[i];
                if (p > currentNum) break;
                temp = currentNum / p;
                if (temp * p == currentNum)
                {
                    currentNum = temp;
                    i--;
                    if (prevP != p) { prevP = p; totient -= (totient / p); }
                }
            }
            return totient;
        }

    }
}
