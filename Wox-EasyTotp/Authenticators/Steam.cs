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

					uint iFullCode = GetFullCode(vHashData);

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
