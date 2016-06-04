using System;
using System.Text;

namespace Wox_EasyTotp.Authenticators
{
	[Authenticator("TOTP Steam", "Images/steam.png")]
	class Steam : RFC6238
	{
		static string GetCode(string sSecretKey)
		{
			if (sSecretKey.Length == 32)
			{
				try
				{
					long iInterval = GetInterval(DateTime.Now);
					byte[] vHashData = DescryptTime(sSecretKey, (ulong)iInterval);

					int iStart = vHashData[19] & 0x0f;

					// extract those 4 bytes
					byte[] vData = new byte[4];
					Array.Copy(vHashData, iStart, vData, 0, 4);
					if (BitConverter.IsLittleEndian)
					{
						Array.Reverse(vData);
					}
					uint iFullCode = BitConverter.ToUInt32(vData, 0) & 0x7fffffff;

					const string sSteamChars = "23456789BCDFGHJKMNPQRTVWXY";
					StringBuilder sCodeBuilder = new StringBuilder();
					for (var i = 0; i < 5; i++)
					{
						sCodeBuilder.Append(sSteamChars[(int)(iFullCode % sSteamChars.Length)]);
						iFullCode /= (uint)sSteamChars.Length;
					}

					return sCodeBuilder.ToString();
				}
				catch { }
			}
			return null;
		}
	}
}
