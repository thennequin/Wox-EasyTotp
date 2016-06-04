using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Text;
using System.Windows.Forms;

using Wox.Plugin;

namespace Wox_EasyTotp
{
	public class Main : IPlugin//, IPluginI18n
	{
		private PluginInitContext context;

		public void Init(PluginInitContext context)
		{
			this.context = context;
		}

		public List<Result> Query(Query query)
		{
			List<Result> results = new List<Result>();

			if (query.RawQuery.Length >= 16)
			{
				try
				{
					long iInterval = GetInterval(DateTime.Now);

					byte[] hash = DescryptTime(query.RawQuery, (ulong)iInterval);
					string sCode = GetClassicCode(hash);
					results.Add(new Result()
					{
						Title = sCode,
						SubTitle = "TOTP - Classic",
						IcoPath = "Images\\lock.png",  //relative path to your plugin directory
						Action = e =>
						{
							Clipboard.SetText(sCode);
							return true;
						}
					});

					sCode = GetSteamCode(hash);
					results.Add(new Result()
					{
						Title = sCode,
						SubTitle = "TOTP - Steam",
						IcoPath = "Images\\lock.png",  //relative path to your plugin directory
						Action = e =>
						{
							Clipboard.SetText(sCode);
							return true;
						}
					});

				}
				catch (Exception e)
				{ }
			}

			return results;
		}

		private long GetInterval(DateTime dateTime, int iIntervalSeconds = 30)
		{
			TimeSpan ts = (dateTime.ToUniversalTime() - new DateTime(1970, 1, 1, 0, 0, 0, DateTimeKind.Utc));
			return (long)ts.TotalSeconds / iIntervalSeconds;
		}


		byte[] DescryptTime(string secret, ulong challengeValue)
		{
			ulong chlg = challengeValue;
			byte[] challenge = new byte[8];
			for (int j = 7; j >= 0; j--)
			{
				challenge[j] = (byte)((int)chlg & 0xff);
				chlg >>= 8;
			}

			var key = Base32Encoding.ToBytes(secret);
			for (int i = secret.Length; i < key.Length; i++)
			{
				key[i] = 0;
			}

			HMACSHA1 mac = new HMACSHA1(key);
			return mac.ComputeHash(challenge);
		}

		protected string GetClassicCode(byte[] hash)
		{
			int offset = hash[hash.Length - 1] & 0xf;

			int truncatedHash = 0;
			for (int j = 0; j < 4; j++)
			{
				truncatedHash <<= 8;
				truncatedHash |= hash[offset + j];
			}

			truncatedHash &= 0x7FFFFFFF;
			truncatedHash %= 1000000;

			string code = truncatedHash.ToString();
			return code.PadLeft(6, '0');
		}

		protected string GetSteamCode(byte[] hash)
		{
			int start = hash[19] & 0x0f;

			// extract those 4 bytes
			byte[] bytes = new byte[4];
			Array.Copy(hash, start, bytes, 0, 4);
			if (BitConverter.IsLittleEndian)
			{
				Array.Reverse(bytes);
			}
			uint fullcode = BitConverter.ToUInt32(bytes, 0) & 0x7fffffff;

			const string sSteamChars = "23456789BCDFGHJKMNPQRTVWXY";
			StringBuilder code = new StringBuilder();
			for (var i = 0; i < 5; i++)
			{
				code.Append(sSteamChars[(int)(fullcode % sSteamChars.Length)]);
				fullcode /= (uint)sSteamChars.Length;
			}

			return code.ToString();
		}
	}
}
