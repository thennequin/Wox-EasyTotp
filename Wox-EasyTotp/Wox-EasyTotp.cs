using System;
using System.Collections.Generic;
using System.Reflection;
using System.Text;
using System.Windows.Forms;

using Wox.Plugin;

namespace Wox_EasyTotp
{
	public class Main : IPlugin
	{
		class AuthenticatorInfo
		{
			public AuthenticatorInfo(string sName, string sIcon, MethodInfo oMethodInfo)
			{
				m_sName = sName;
				m_sIcon = sIcon;
				m_oMethodInfo = oMethodInfo;
			}
			public string m_sName;
			public string m_sIcon;
			public MethodInfo m_oMethodInfo;
		}

		private PluginInitContext m_oContext;
		private List<AuthenticatorInfo> m_lMethods = new List<AuthenticatorInfo>();

		public void Init(PluginInitContext context)
		{
			this.m_oContext = context;

			Assembly oAssembly = Assembly.GetAssembly(typeof(AuthenticatorAttribute));
			foreach (Type oType in oAssembly.GetTypes())
			{
				object[] vAttributes = oType.GetCustomAttributes(typeof(AuthenticatorAttribute), false);
				if (vAttributes.Length == 1)
				{
					MethodInfo oMethodInfo = oType.GetMethod("GetCode", BindingFlags.Static | BindingFlags.NonPublic);
					if (null != oMethodInfo)
					{
						ParameterInfo[] vParameters = oMethodInfo.GetParameters();
						if (oMethodInfo.ReturnType == typeof(string)
							&& vParameters != null
							&& vParameters.Length == 1
							&& vParameters[0].ParameterType == typeof(string))
						{
							AuthenticatorAttribute oAttribute = (AuthenticatorAttribute)vAttributes[0];
							m_lMethods.Add(new AuthenticatorInfo(oAttribute.m_sName, oAttribute.m_sIcon, oMethodInfo));
						}
					}
				}
			}
		}

		public List<Result> Query(Query query)
		{
			List<Result> results = new List<Result>();

			object[] oParams = new object[] { query.RawQuery };
			foreach (AuthenticatorInfo oInfo in m_lMethods)
			{
				string sCodeRes = (string)oInfo.m_oMethodInfo.Invoke(null, oParams);
				if (sCodeRes != null)
				{
					results.Add(new Result()
					{
						Title = sCodeRes,
						SubTitle = oInfo.m_sName,
						IcoPath = oInfo.m_sIcon,
						Action = e =>
						{
							Clipboard.SetText(sCodeRes);
							return true;
						}
					});
				}
			}
			return results;
		}
	}
}
