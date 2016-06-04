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

					int iOffset = vHashData[vHashData.Length - 1] & 0xf;

					int iTruncatedHash = 0;
					for (int j = 0; j < 4; j++)
					{
						iTruncatedHash <<= 8;
						iTruncatedHash |= vHashData[iOffset + j];
					}

					iTruncatedHash &= 0x7FFFFFFF;
					iTruncatedHash %= 1000000;

					string sCode = iTruncatedHash.ToString();
					return sCode.PadLeft(6, '0');
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
			byte[] vChallengeData = new byte[8];
			for (int j = 7; j >= 0; j--)
			{
				vChallengeData[j] = (byte)((int)iChallengeValue & 0xff);
				iChallengeValue >>= 8;
			}

			byte[] vKeyData = Base32Encoding.ToBytes(sSecret);
			for (int i = sSecret.Length; i < vKeyData.Length; i++)
			{
				vKeyData[i] = 0;
			}

			HMACSHA1 oMac = new HMACSHA1(vKeyData);
			return oMac.ComputeHash(vChallengeData);
		}
	}
}
