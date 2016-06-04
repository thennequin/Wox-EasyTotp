using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Wox_EasyTotp
{
	class AuthenticatorAttribute : Attribute
	{
		public string m_sName;
		public string m_sIcon;

		public AuthenticatorAttribute(string sName, string sIcon)
		{
			m_sName = sName;
			m_sIcon = sIcon;
		}
	}
}
