using System;
using System.Text;

namespace Wox_EasyTotp.Authenticators
{
	[Authenticator("TOTP Battle.Net", "Images/battlenet.png")]
	class BattleNet : RFC6238
	{
		static string GetCode(string sSecretKey)
		{
			String sDecodedSecretKey = null;

			/*if (sSecretKey.Length == 17) // Serial number
			{
				//TODO
			}
			else if (sSecretKey.Length == 10) // Restore code
			{
				//TODO
			}
			else*/ if (sSecretKey.Length == 114)
			{
				const String sMask = "398e27fc50276a656065b0e525f4c06c04c61075286b8e7aeda59da9813b5dd6c80d2fb38068773fa59ba47c17ca6c6479015c1d5b8b8f6b9a";

				byte[] secretKey = StringToByteArray(sSecretKey.Substring(0, 80));
				//byte[] serial = StringToByteArray(sSecretKey.Substring(80));
				byte[] maskBytes = StringToByteArray(sMask);

				/*
				byte[] decodedSerial = new byte[serial.Length];
				for (int i = 0; i < serial.Length; ++i)
				{
					decodedSerial[i] = (byte)(serial[i] ^ maskBytes[40 + i]);
				}
				String decodedSerialString = ASCIIEncoding.UTF8.GetString(decodedSerial);
				*/

				byte[] decodedSecretKey = new byte[secretKey.Length];
				for (int i = 0; i < secretKey.Length; ++i)
				{
					decodedSecretKey[i] = (byte)(secretKey[i] ^ maskBytes[i]);
				}
				String decodedSecretKeyString = ASCIIEncoding.ASCII.GetString(decodedSecretKey);

				sDecodedSecretKey = decodedSecretKeyString;
			}
			else if (sSecretKey.Length == 40) //Decrypted key
			{
				sDecodedSecretKey = sSecretKey;
			}

			if (sDecodedSecretKey != null)
			{
				try
				{
					long iInterval = GetInterval(DateTime.Now);
					byte[] vHashData = DescryptTime(StringToByteArray(sDecodedSecretKey), (ulong)iInterval);

					uint iFullCode = GetFullCode(vHashData);
					return GetDigitsCode(iFullCode, 8);
				}
				catch { }
			}

			return null;
		}

		static byte[] StringToByteArray(string hex)
		{
			int len = hex.Length;
			byte[] bytes = new byte[len / 2];
			for (int i = 0; i < len; i += 2)
			{
				bytes[i / 2] = Convert.ToByte(hex.Substring(i, 2), 16);
			}
			return bytes;
		}
	}
}
