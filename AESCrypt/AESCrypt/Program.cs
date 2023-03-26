using System;
using System.Collections;
using System.IO;
using System.Text;

namespace test_createkey
{
    class Program
    {
        //my Key
        public static byte[] key = new byte[] { 0x2b, 0x28, 0xab, 0x09, 0x7e, 0xae, 0xf7, 0xcf, 0x15, 0xd2, 0x15, 0x4f, 0x16, 0xa6, 0x88, 0x3c };
        //Rcon
        static readonly byte[] Rcon = new byte[10] { 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36 };
        
        
        //ENCODE----------------
        //Sbox 
        private static readonly byte[] SBox =
            {
            0x63,  0x7c,  0x77,  0x7b,  0xf2,  0x6b,  0x6f,  0xc5,  0x30,  0x01,  0x67,  0x2b,  0xfe,  0xd7,  0xab,  0x76,
            0xca,  0x82,  0xc9,  0x7d,  0xfa,  0x59,  0x47,  0xf0,  0xad,  0xd4,  0xa2,  0xaf,  0x9c,  0xa4,  0x72,  0xc0,
            0xb7,  0xfd,  0x93,  0x26,  0x36,  0x3f,  0xf7,  0xcc,  0x34,  0xa5,  0xe5,  0xf1,  0x71,  0xd8,  0x31,  0x15,
            0x04,  0xc7,  0x23,  0xc3,  0x18,  0x96,  0x05,  0x9a,  0x07,  0x12,  0x80,  0xe2,  0xeb,  0x27,  0xb2,  0x75,
            0x09,  0x83,  0x2c,  0x1a,  0x1b,  0x6e,  0x5a,  0xa0,  0x52,  0x3b,  0xd6,  0xb3,  0x29,  0xe3,  0x2f,  0x84,
            0x53,  0xd1,  0x00,  0xed,  0x20,  0xfc,  0xb1,  0x5b,  0x6a,  0xcb,  0xbe,  0x39,  0x4a,  0x4c,  0x58,  0xcf,
            0xd0,  0xef,  0xaa,  0xfb,  0x43,  0x4d,  0x33,  0x85,  0x45,  0xf9,  0x02,  0x7f,  0x50,  0x3c,  0x9f,  0xa8,
            0x51,  0xa3,  0x40,  0x8f,  0x92,  0x9d,  0x38,  0xf5,  0xbc,  0xb6,  0xda,  0x21,  0x10,  0xff,  0xf3,  0xd2,
            0xcd,  0x0c,  0x13,  0xec,  0x5f,  0x97,  0x44,  0x17,  0xc4,  0xa7,  0x7e,  0x3d,  0x64,  0x5d,  0x19,  0x73,
            0x60,  0x81,  0x4f,  0xdc,  0x22,  0x2a,  0x90,  0x88,  0x46,  0xee,  0xb8,  0x14,  0xde,  0x5e,  0x0b,  0xdb,
            0xe0,  0x32,  0x3a,  0x0a,  0x49,  0x06,  0x24,  0x5c,  0xc2,  0xd3,  0xac,  0x62,  0x91,  0x95,  0xe4,  0x79,
            0xe7,  0xc8,  0x37,  0x6d,  0x8d,  0xd5,  0x4e,  0xa9,  0x6c,  0x56,  0xf4,  0xea,  0x65,  0x7a,  0xae,  0x08,
            0xba,  0x78,  0x25,  0x2e,  0x1c,  0xa6,  0xb4,  0xc6,  0xe8,  0xdd,  0x74,  0x1f,  0x4b,  0xbd,  0x8b,  0x8a,
            0x70,  0x3e,  0xb5,  0x66,  0x48,  0x03,  0xf6,  0x0e,  0x61,  0x35,  0x57,  0xb9,  0x86,  0xc1,  0x1d,  0x9e,
            0xe1,  0xf8,  0x98,  0x11,  0x69,  0xd9,  0x8e,  0x94,  0x9b,  0x1e,  0x87,  0xe9,  0xce,  0x55,  0x28,  0xdf,
            0x8c,  0xa1,  0x89,  0x0d,  0xbf,  0xe6,  0x42,  0x68,  0x41,  0x99,  0x2d,  0x0f,  0xb0,  0x54,  0xbb,  0x16
        };
        private static readonly byte[] InvSBox = new byte[]
{
        0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
        0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
        0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
        0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
        0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
        0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
        0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
        0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
        0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
        0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
        0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
        0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
        0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
        0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
        0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
        0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d,
};

        //Read key in file
        public static int ReadKeyInFile()
        {
            string keyString =  File.ReadAllText("key.txt");
            if (keyString.Length < 16)
            {
                Console.WriteLine("key length less than 16 bytes !!!!!!!!");
                key = padPlaintext(Encoding.UTF8.GetBytes(keyString), 16);
                //Console.WriteLine("key: " + BitConverter.ToString(key));
                return 1;
            }
            if(keyString.Length > 16)
            {
                
                return -1;
            }
            key = Encoding.UTF8.GetBytes(keyString);
            return 1;
        }
        public static int ReadKeyInKeyboard()
        {
            string keyString = Console.ReadLine();
            //byte[] s1 = Encoding.UTF8.GetBytes(keyString);
            if (keyString.Length < 16)
            {
                key = padPlaintext(Encoding.UTF8.GetBytes(keyString), 16);
            }
            else key = Encoding.UTF8.GetBytes(keyString);
            return keyString.Length;

        }
        public static byte[] ExecuteAES(string s)
        {

            double firsttime1 = Convert.ToDouble(DateTime.Now.ToString("ss.ffff"));
            int index = s.Length / 16;
            int mod = s.Length % 16;
            Console.WriteLine("Data: \n"+s);
            Console.WriteLine("Encode process...\n");
            string totalString = null;
            byte[,] encodeMod;
            //ArrayList ArrayEncode = new ArrayList();
            File.WriteAllText("encrypted.hex", null);
            if (s.Length > 0 )
            {
                int i = 0;
                string s1;
                
                int pos = 0;
                for(int n = 0; n < index; n++)
                {
                    s1 = s.Substring(i+(n*16),16);
                    Console.WriteLine(s1);
                    pos = i + (n * 16);
                    //ArrayEncode.Add(EncodeAES(convertArray(Encoding.UTF8.GetBytes(s1))));
                    byte[] save = un_convertArray(EncodeAES(convertArray(Encoding.UTF8.GetBytes(s1))));
                    string cleanedHexString = BitConverter.ToString(save).Replace("-", "");
                    File.AppendAllText("encrypted.hex",cleanedHexString);
                    totalString += ByteToString(convertArray(save));
                    Console.WriteLine(BitConverter.ToString(save));

                }
            }
            
            string s2 = s.Substring(index*16, mod);
            Console.WriteLine(s2);
            encodeMod = EncodeAES(convertArray(padPlaintext(Encoding.UTF8.GetBytes(s2), 16)));
            Console.WriteLine(BitConverter.ToString(un_convertArray(encodeMod)));

            File.AppendAllText("encrypted.hex", BitConverter.ToString(un_convertArray(encodeMod)).Replace("-", ""));
            totalString += ByteToString(EncodeAES(convertArray(padPlaintext(Encoding.UTF8.GetBytes(s2), 16))));
            double lastTime1 = Convert.ToDouble(DateTime.Now.ToString("ss.ffff"));
            Console.WriteLine("Encrypted: \n"+File.ReadAllText("encrypted.hex"));
            Console.WriteLine("String encryted:");
            Console.WriteLine(totalString);
            Console.WriteLine("Time encrypt: "+(lastTime1-firsttime1)+"s");
            byte[] savex = new byte[1];
            return savex;

        }
        public static void ExecuteAES_decode(string s)
        {
            string dataInput = File.ReadAllText("data_decode.hex");
            s = dataInput;
            Console.WriteLine("Data:");
            Console.WriteLine(dataInput);
            Console.WriteLine("Decode process....\n");
            int index = s.Length / 32;
            int mod = s.Length % 32;
            File.WriteAllText("decrypted.hex", null);
            byte[] dataConverted = stringToHexa(dataInput);

            double firstTime2 = Convert.ToDouble(DateTime.Now.ToString("ss.ffff"));
            string totalString2 = null;


            int i = 0;
            string getEach16bytes;
            int pos = 0;
            for (int n = 0; n < index; n++)
            {
                getEach16bytes = s.Substring(i + (n * 32), 32);
                pos = i + (n * 32);
                Console.WriteLine(getEach16bytes);
                byte[] decodeEach = stringToHexa(getEach16bytes);
                byte[] decrypted = un_convertArray(DecodeAES(convertArray(decodeEach)));
                File.AppendAllText("decrypted.hex", BitConverter.ToString(decrypted).Replace("-", ""));
                Console.WriteLine(BitConverter.ToString(decrypted));
            }
            //string b = s.Substring(index * 32, mod);
            //Console.WriteLine(s.Substring(index * 32, mod));
            //byte[] decodeMod = un_convertArray(DecodeAES(convertArray(padPlaintext(stringToHexa(b), 16))));
            //Console.WriteLine(BitConverter.ToString(decodeMod));
            //File.AppendAllText("decrypted.hex", BitConverter.ToString(decodeMod).Replace("-", ""));
            Console.WriteLine("\nDecrypted: "+File.ReadAllText("decrypted.hex"));
            double lastTime2 = Convert.ToDouble(DateTime.Now.ToString("ss.ffff"));
            Console.WriteLine("Time encode: "+(lastTime2-firstTime2)+"s");
        }
        //Padding input 16 byte
        public static byte[] padPlaintext(byte[] plaintext, int blockSize)
        {
            int paddingLength = blockSize - (plaintext.Length % blockSize);
            byte paddingByte = (byte)paddingLength;
            byte[] paddedPlaintext = new byte[plaintext.Length + paddingLength];
            Array.Copy(plaintext, 0, paddedPlaintext, 0, plaintext.Length);
            for (int i = plaintext.Length; i < paddedPlaintext.Length; i++)
            {
                paddedPlaintext[i] = (byte)paddingByte;
            }
            return paddedPlaintext;
        }

        //Subbytes 
        public static byte[,] SubBytes(byte[,] input)
        {
            byte[,] result = new byte[4, 4];

            for (int row = 0; row < 4; row++)
            {
                for (int col = 0; col < 4; col++)
                {
                    byte b = input[row, col];
                    byte s = SBox[b];
                    result[row, col] = s;
                }
            }
            return result;
        }
        //MixColumns
        private static byte[,] MixColumns(byte[,] state)
        {
            byte[,] result = new byte[4, 4];

            for (int i = 0; i < 4; i++)
            {
                byte s0 = state[0, i], s1 = state[1, i], s2 = state[2, i], s3 = state[3, i];

                result[0, i] = (byte)(GF28Multiply(s0, 0x02) ^ GF28Multiply(s1, 0x03) ^ s2 ^ s3);
                result[1, i] = (byte)(s0 ^ GF28Multiply(s1, 0x02) ^ GF28Multiply(s2, 0x03) ^ s3);
                result[2, i] = (byte)(s0 ^ s1 ^ GF28Multiply(s2, 0x02) ^ GF28Multiply(s3, 0x03));
                result[3, i] = (byte)(GF28Multiply(s0, 0x03) ^ s1 ^ s2 ^ GF28Multiply(s3, 0x02));
            }

            return result;
        }
        private static byte GF28Multiply(byte a, byte b)
        {
            byte p = 0;
            byte hbit = 0;

            for (int i = 0; i < 8; i++)
            {
                if ((b & 1) == 1)
                {
                    p ^= a;
                }

                hbit = (byte)(a & 0x80);
                a <<= 1;

                if (hbit == 0x80)
                {
                    a ^= 0x1B;
                }

                b >>= 1;
            }

            return p;
        }
        //Convert 1D array to 2D array
        public static byte[,] convertArray(byte[] input)
        {
            byte[,] output = new byte[4, 4];
            int position = 0;
            for (int i = 0; i < 4; i++)
            {
                for (int j = 0; j < 4; j++)
                {
                    output[i, j] = input[position];
                    position++;
                }
            }
            return output;

        }
        //Add RoundKey
        public static byte[,] AddRoundKey(byte[,] state, byte[,] roundKey)
        {
            for (int c = 0; c < 4; c++)
            {
                for (int r = 0; r < 4; r++)
                {
                    state[r, c] ^= roundKey[r, c];
                }
            }
            return state;
        }
        //ShiftRows
        public static byte[,] shiftRows(byte[,] input)
        {
            byte[,] output = new byte[4, 4];
            for (int i = 0; i < 4; i++)
            {
                output[0, i] = input[0, i];
            }
            //second line
            output[1, 0] = input[1, 1];
            output[1, 1] = input[1, 2];
            output[1, 2] = input[1, 3];
            output[1, 3] = input[1, 0];
            //third line
            output[2, 0] = input[2, 2];
            output[2, 1] = input[2, 3];
            output[2, 2] = input[2, 0];
            output[2, 3] = input[2, 1];
            //fourth line
            output[3, 0] = input[3, 3];
            output[3, 1] = input[3, 0];
            output[3, 2] = input[3, 1];
            output[3, 3] = input[3, 2];
            return output;
        }
        
        
        //Create new roundkey
        public static byte[] key_xorArray(byte[] arr1, byte[] arr2, int round)
        {
            byte[] result = new byte[arr1.Length];
            byte[] SubRcon = new byte[4];
            SubRcon[0] = Rcon[round + 1];
            for (int i = 1; i < 4; i++)
            {
                SubRcon[i] = 0x00;
            }
            //Console.WriteLine("Rcon: " + BitConverter.ToString(SubRcon));
            for (int i = 0; i < arr1.Length; i++)
            {
                result[i] = (byte)(arr1[i] ^ arr2[i] ^ SubRcon[i]);
            }
            //Console.WriteLine("XOR of both arrays: " + BitConverter.ToString(result));
            return result;
        }//XOR use Rcon
        public static byte[] key_rotWord(byte[] arr)
        {
            byte[] result = new byte[arr.Length];
            result[0] = arr[1];
            result[1] = arr[2];
            result[2] = arr[3];
            result[3] = arr[0];
            //Console.WriteLine("Rotword arrays: " + BitConverter.ToString(result));
            return result;
        }//Rotword
        public static byte[] key_SubBytes(byte[] state)
        {
            byte[] result = new byte[4];


            for (int i = 0; i < 4; i++)
            {
                byte b = state[i];
                byte s = SBox[b];
                result[i] = s;
            }
            //Console.WriteLine("Subbytes arrays: " + BitConverter.ToString(result));
            return result;
        }//Subbytes
        public static byte[] key_xorNormal(byte[] arr1, byte[] arr2)
        {
            byte[] result = new byte[arr1.Length];
            for (int i = 0; i < arr1.Length; i++)
            {
                result[i] = (byte)(arr1[i] ^ arr2[i]);
            }
            //Console.WriteLine("XOR of both arrays: " + BitConverter.ToString(result));
            return result;
        }//XOR without rcon
        public static byte[] firstColumnKey(byte[] previewkey, int round)
        {
            byte[,] keyArray2D = convertArray(previewkey);
            byte[] lastPieceKey = new byte[4];
            byte[] firstPieceKey = new byte[4];

            int n = 0;
            for (int i = 3; i < 16; i = i + 4)
            {
                lastPieceKey[n] = previewkey[i];
                n++;
            }
            n = 0;
            for (int j = 0; j < 16; j = j + 4)
            {
                firstPieceKey[n] = previewkey[j];
                n++;
            }
            //Console.WriteLine("first: " + BitConverter.ToString(firstPieceKey));//dlt
            byte[] roted = key_rotWord(lastPieceKey);
            //Console.WriteLine("rot: " + BitConverter.ToString(roted));//dlt

            byte[] subed = key_SubBytes(roted);
            //Console.WriteLine("sub: " + BitConverter.ToString(subed));//dlt

            byte[] xored = key_xorArray(firstPieceKey, subed, round - 1);
            //Console.WriteLine("xor: " + BitConverter.ToString(xored));//dlt

            //byte[,] result = new byte[4, 4];
            //Console.WriteLine("first: " + BitConverter.ToString(xored));
            //Console.WriteLine("\n\n\n");
            return xored;
        }//First column of new key
        public static byte[] getColumnOfKey(byte[] key, int column)
        {
            byte[] output = new byte[4];
            int position = 0;
            for (int i = 0; i < 16; i = i + 4)
            {
                output[position] = key[column + i - 1];
                position++;
            }
            //Console.WriteLine("Column "+column+": " + BitConverter.ToString(output));
            return output;
        }//Get column in key (key is 1D array)
        public static byte[,] rowToColumn(byte[,] input)
        {
            byte[,] output = new byte[4, 4];
            int rows = input.GetLength(0);
            int cols = input.GetLength(1);

            for (int i = 0; i < 4; i++)
            {
                for (int j = 0; j < 4; j++)
                {
                    output[i, j] = input[j, i];
                }
            }

            return output;
        }//Matrix ^ T
        public static byte[] un_convertArray(byte[,] array)
        {
            byte[] result = new byte[16];
            int position = 0;
            for (int i = 0; i < 4; i++)
            {
                for (int j = 0; j < 4; j++)
                {
                    result[position] = array[i, j];
                    position++;
                }
            }
            return result;
        }//
        public static byte[,] getRoundKeyByID(int i)
        {
            byte[,] key0 = nextRoundKey(convertArray(Program.key), 0);
            byte[,] key1 = nextRoundKey(key0, 1);
            byte[,] key2 = nextRoundKey(key1, 2);
            byte[,] key3 = nextRoundKey(key2, 3);
            byte[,] key4 = nextRoundKey(key3, 4);
            byte[,] key5 = nextRoundKey(key4, 5);
            byte[,] key6 = nextRoundKey(key5, 6);
            byte[,] key7 = nextRoundKey(key6, 7);
            byte[,] key8 = nextRoundKey(key7, 8);
            byte[,] key9 = nextRoundKey(key8, 9);
            if (i == 0) return key0;
            if (i == 1) return key1;
            if (i == 2) return key2;
            if (i == 3) return key3;
            if (i == 4) return key4;
            if (i == 5) return key5;
            if (i == 6) return key6;
            if (i == 7) return key7;
            if (i == 8) return key8;
            if (i == 9) return key9;
            else return key0;
            
        }
        public static byte[,] nextRoundKey(byte[,] previewKey, int round)
        {
            // Chỉ thái đẹp zai mới hỉu :>
            int stt = round + 1;
            //Console.WriteLine("-----------------round: " + stt);
            byte[] c2_old = getColumnOfKey(un_convertArray(previewKey), 2);
            //Console.WriteLine("unconvert 2: " + BitConverter.ToString(c2_old));

            byte[] c3_old = getColumnOfKey(un_convertArray(previewKey), 3);
            //Console.WriteLine("unconvert 3 : " + BitConverter.ToString(c3_old));

            byte[] c4_old = getColumnOfKey(un_convertArray(previewKey), 4);
            //Console.WriteLine("unconvert 4 : " + BitConverter.ToString(c4_old));

            byte[] c1_new = firstColumnKey(un_convertArray(previewKey), round);// round?
            //Console.WriteLine("unconvert1 : " + BitConverter.ToString(c1_new));

            byte[] c2_new = key_xorNormal(c1_new, c2_old);
            //Console.WriteLine("new column 2 : " + BitConverter.ToString(c2_new));
            byte[] c3_new = key_xorNormal(c2_new, c3_old);
            //Console.WriteLine("new column 3 : " + BitConverter.ToString(c3_new));
            byte[] c4_new = key_xorNormal(c3_new, c4_old);
            //Console.WriteLine("new column 4 : " + BitConverter.ToString(c4_new));
            byte[,] result = new byte[4, 4];
            for (int i = 0; i < 4; i++)
            {
                result[0, i] = c1_new[i];
                result[1, i] = c2_new[i];
                result[2, i] = c3_new[i];
                result[3, i] = c4_new[i];
            }
            result = rowToColumn(result);
            //Console.WriteLine("\n\n\n");
            //for (int i = 0; i < result.GetLength(0); i++)
            //{
            //    for (int j = 0; j < result.GetLength(1); j++)
            //    {
            //        Console.Write(result[i, j].ToString("X2") + " ");
            //    }
            //    Console.WriteLine();
            //}
            //Console.WriteLine("\n\n\n");
            return result;
        }

        //DECODE-------------------------
        static byte[,] UnMixColumns(byte[,] state)
        {
            for (int i = 0; i < 4; i++)
            {
                byte[] col = new byte[4];
                for (int j = 0; j < 4; j++)
                {
                    col[j] = state[j, i];
                }
                byte[] tmp = new byte[4];
                tmp[0] = (byte)(Mul(col[0], 0x0E) ^ Mul(col[1], 0x0B) ^ Mul(col[2], 0x0D) ^ Mul(col[3], 0x09));
                tmp[1] = (byte)(Mul(col[0], 0x09) ^ Mul(col[1], 0x0E) ^ Mul(col[2], 0x0B) ^ Mul(col[3], 0x0D));
                tmp[2] = (byte)(Mul(col[0], 0x0D) ^ Mul(col[1], 0x09) ^ Mul(col[2], 0x0E) ^ Mul(col[3], 0x0B));
                tmp[3] = (byte)(Mul(col[0], 0x0B) ^ Mul(col[1], 0x0D) ^ Mul(col[2], 0x09) ^ Mul(col[3], 0x0E));
                for (int j = 0; j < 4; j++)
                {
                    state[j, i] = tmp[j];
                }

            }
            return state;
        } //UnMixColumns

        static byte Mul(byte a, byte b)
        {
            byte p = 0;
            byte hi_bit_set;
            for (int i = 0; i < 8; i++)
            {
                if ((b & 1) == 1)
                {
                    p ^= a;
                }
                hi_bit_set = (byte)(a & 0x80);
                a <<= 1;
                if (hi_bit_set == 0x80)
                {
                    a ^= 0x1B;
                }
                b >>= 1;
            }
            return p;
        } //submethod unmixcolumns
        static byte[,] UnShiftRows(byte[,] input)
        {
            byte[,] output = new byte[4, 4];
            for (int i = 0; i < 4; i++)
            {
                output[0, i] = input[0, i];
            }
            output[1, 1] = input[1, 0];
            output[1, 2] = input[1, 1];
            output[1, 3] = input[1, 2];
            output[1, 0] = input[1, 3];
            //third line
            output[2, 2] = input[2, 0];
            output[2, 3] = input[2, 1];
            output[2, 0] = input[2, 2];
            output[2, 1] = input[2, 3];
            //fourth line
            output[3, 3] = input[3, 0];
            output[3, 0] = input[3, 1];
            output[3, 1] = input[3, 2];
            output[3, 2] = input[3, 3];

            return output;
        } //UnshiftRows
        static byte[,] UnSubBytes(byte[,] state)
        {
            for (int i = 0; i < 4; i++)
            {
                for (int j = 0; j < 4; j++)
                {
                    state[i, j] = InvSBox[state[i, j]];
                }
            }
            return state;
        } //UnSubbytes
        public static byte[,] DecodeAES(byte[,] input)
        {
            byte[,] step1 = AddRoundKey(getRoundKeyByID(9),input);         
            byte[,] step2 = UnShiftRows(step1);         
            byte[,] step3 = new byte[4, 4];
            byte[,] step4 = UnSubBytes(step2);
            for (int i = 8; i > -1; i--)
            {
                step1 = AddRoundKey(step4, getRoundKeyByID(i));
                step2 = UnMixColumns(step1);
                step3 = UnShiftRows(step2);
                step4 = UnSubBytes(step3);
            }
            byte[,] resultDecode = AddRoundKey(step4, convertArray(Program.key));
            string str = Encoding.UTF8.GetString(un_convertArray(resultDecode));
            return resultDecode;

        }

        //Encode-----------------
        public static byte[,] EncodeAES(byte[,] input)
        {

            byte[,] convertArray_key = convertArray(key);
            byte[,] convertArray_data = input;

            //Convertsely 
            byte[,] step1 = new byte[4, 4];
            byte[,] step2 = new byte[4, 4];
            byte[,] step3 = new byte[4, 4];
            byte[,] step4 = new byte[4, 4];
            byte[,] step5 = new byte[4, 4];
            step1 = AddRoundKey(convertArray_data, convertArray_key);
            for (int i = 0; i < 10; i++)
            {
                convertArray_key = nextRoundKey(convertArray_key, i);
                //Subbytes
                //for (int g = 0; g < convertArray_key.GetLength(0); g++)
                //{
                //    for (int j = 0; j < convertArray_key.GetLength(1); j++)
                //    {
                //        Console.Write(convertArray_key[g, j].ToString("X2") + " ");
                //    }
                //    Console.WriteLine();
                //}
                //Console.WriteLine("\n\n\n");
                step2 = SubBytes(step1);
                step3 = shiftRows(step2);
                //Mixcolumn
                if (i == 9)
                {
                    break;
                }
                step4 = MixColumns(step3);
                //Addroundkey
                step1 = AddRoundKey(step4, convertArray_key);
            }
            

            byte[,] last = AddRoundKey(step3, convertArray_key);
            return last;

        }
        public static string ByteToString(byte[,] input)
        {
            return Encoding.UTF8.GetString(un_convertArray(input));
        }
        public static byte[] stringToHexa(string hexString)
        {
            byte[] byteArray = new byte[hexString.Length / 2];

            for (int i = 0; i < hexString.Length; i += 2)
            {
                byteArray[i / 2] = Convert.ToByte(hexString.Substring(i, 2), 16);
            }
            return byteArray;
        }
        static void Main(string[] args)
        {
            //ExecuteAES_decode("hello");

            //string ng = "3132333435363738394041424344454647484950515253";
            //byte[] x = new byte[3];
            //x = stringToHexa(ng);
            //string cleanedHexString = BitConverter.ToString(x);
            //Console.WriteLine(cleanedHexString);
            //Console.WriteLine(Encoding.UTF8.GetString(x));
            
            int choice;

            do
            {
                Console.WriteLine("-----Menu------");
                Console.WriteLine("1,ENCODE\n2,DECODE\n3,CHANGE KEY\n4,ENTER DATA");
                choice = Convert.ToInt32(Console.ReadLine());
                int check = ReadKeyInFile();
                switch (choice)
                {
                    case 1:
                        {
                            if(check == 1)
            {
                                File.WriteAllText("encrypted.hex", null);
                                ExecuteAES(File.ReadAllText("data.txt"));
                            }
                            else
                            {
                                Console.WriteLine("Key length longger than 16 bytes -_- !!!!");
                            }
                            break;
                        }
                    case 2:
                        {
                            string dataIn = File.ReadAllText("data_decode.hex");
                            if(dataIn.Length%16 != 0)
                            {
                                Console.WriteLine("Cant decrypt because this input not enough!");
                            }
                            else
                            {
                                ExecuteAES_decode("....");
                            }
                            break;
                        }
                    case 3:
                        {
                            Console.WriteLine("Enter your key: ");
                            string keyIn = Console.ReadLine();
                            File.WriteAllText("key.txt", keyIn);
                            ReadKeyInFile();
                            break;
                        }
                    case 4:
                        {
                            Console.Clear();
                            Console.WriteLine("1, Enter data you want encrypt\n2, Enter data you want decrypt");
                            int choice1 = Convert.ToInt32(Console.ReadLine());
                            if(choice1 == 1)
                            {
                                Console.WriteLine("Enter data: ");
                                string dataIn_encode = Console.ReadLine();
                                File.WriteAllText("data.txt",dataIn_encode);
                            }
                            else
                            {
                                Console.WriteLine("Enter data: ");
                                string dataIn_decode = Console.ReadLine();
                                File.WriteAllText("data_decode.hex", dataIn_decode);
                            }
                            break;
                        }
                    
                }
            }
            while (choice != 0);

        }
    }
}
