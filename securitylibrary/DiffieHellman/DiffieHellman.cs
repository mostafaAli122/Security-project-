using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary.DiffieHellman
{
    public class DiffieHellman 
    {
        public List<int> GetKeys(int q, int alpha, int xa, int xb)
        {

            //userA                 |            userB
            //1)select xA=xa           |            select XB=xb
            //2)calculate ya=alpha^xa % q|   calculate yb=alpha^xb % q
            //3)exchange   ya<-->yb
            //4)key=yb^xa % q             | key=ya^xb %q
            //add keys to list

            int ya = powerfunc(alpha, xa, q);
            int yb = powerfunc(alpha, xb, q);
            int key1 = powerfunc(yb, xa, q);
            int key2 = powerfunc(ya, xb, q);
            List<int> listkeys = new List<int>();
            listkeys.Add( key1);
            listkeys.Add(key2);
            return listkeys;

        }

        public int powerfunc(int Base, int power, int q)
        {  
            Int64 c = 1;
            Int64 NM = 1;
            for (int j = 0; j < power; j++)
            {
                NM = (NM * Base) % q;
            }
            c = NM % q;
            return Convert.ToInt32(c % q);
        }

    }
}
