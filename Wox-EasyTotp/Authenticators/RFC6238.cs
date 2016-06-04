using System;
using System.Security.Cryptography;

namespace Wox_EasyTotp.Authenticators
{
	[Authenticator("TOTP RFC 6238 (Google, Microsoft, ...)", "Images/google.png")]
	class RFC6238
	{
		static string GetCode(string sSecretKey)
		{
			if (sSecretKey.Length >= 16)
			{
				try
				{
					long iInterval = GetInterval(DateTime.Now);
					byte[] vHashData = DescryptTime(sSecretKey, (ulong)iInterval);

					uint iFullCode = GetFullCode(vHashData);
					return GetDigitsCode(iFullCode, 6);
				}
				catch { }
			}
			return null;
		}

		static protected long GetInterval(DateTime oDateTime, int iIntervalSeconds = 30)
		{
			TimeSpan oTimeSpan = (oDateTime.ToUniversalTime() - new DateTime(1970, 1, 1, 0, 0, 0, DateTimeKind.Utc));
			return (long)oTimeSpan.TotalSeconds / iIntervalSeconds;
		}


		static protected byte[] DescryptTime(string sSecret, ulong iChallengeValue)
		{
			byte[] vKeyData = Base32Encoding.ToBytes(sSecret);
			for (int i = sSecret.Length; i < vKeyData.Length; i++)
			{
				vKeyData[i] = 0;
			}

			return DescryptTime(vKeyData, iChallengeValue);
		}

		static protected byte[] DescryptTime(byte[] vKeyData, ulong iChallengeValue)
		{
			byte[] vChallengeData = new byte[8];
			for (int j = 7; j >= 0; j--)
			{
				vChallengeData[j] = (byte)((int)iChallengeValue & 0xff);
				iChallengeValue >>= 8;
			}

			HMACSHA1 oMac = new HMACSHA1(vKeyData);
			return oMac.ComputeHash(vChallengeData);
		}

		static protected uint GetFullCode(byte[] vHashData)
		{
			int iStart = vHashData[vHashData.Length - 1] & 0xf;

			byte[] vBytes = new byte[4];
			Array.Copy(vHashData, iStart, vBytes, 0, 4);
			if (BitConverter.IsLittleEndian)
			{
				Array.Reverse(vBytes);
			}

			return BitConverter.ToUInt32(vBytes, 0) & 0x7fffffff;
		}

		static protected string GetDigitsCode(uint iFullCode, int iDigitCount)
		{
			uint iCodeMask = (uint)Math.Pow(10, iDigitCount);
			string sFormat = new string('0', iDigitCount);
			return (iFullCode % iCodeMask).ToString(sFormat);
		}
	}
}
