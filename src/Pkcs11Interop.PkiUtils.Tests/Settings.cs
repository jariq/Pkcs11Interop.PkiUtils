/*
 *  Pkcs11Interop.PkiUtils - PKI extensions for Pkcs11Interop library
 *  Copyright (c) 2013 JWC s.r.o.
 *  Author: Jaroslav Imrich
 *  
 *  This program is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU Affero General Public License version 3
 *  as published by the Free Software Foundation.
 *  
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 *  GNU Affero General Public License for more details.
 *  
 *  You should have received a copy of the GNU Affero General Public License
 *  along with this program. If not, see <http://www.gnu.org/licenses/>.
 *  
 *  You can be released from the requirements of the license by purchasing
 *  a commercial license. Buying such a license is mandatory as soon as you
 *  develop commercial activities involving the Pkcs11Interop.PkiUtils software 
 *  without disclosing the source code of your own applications.
 *  
 *  For more information, please contact JWC s.r.o. at info@pkcs11interop.net
 */

using System;

namespace Net.Pkcs11Interop.PkiUtils.Tests
{
	/// <summary>
	/// Test settings.
	/// </summary>
	public class Settings
	{
		/// <summary>
		/// The PKCS#11 unmanaged library path
		/// </summary>
		public static string Pkcs11LibraryPath = @"siecap11.dll";

		/// <summary>
		/// Serial number of the token (smartcard) that should be used in these tests. May be null if TokenLabel is specified.
		/// </summary>
		public static string TokenSerial = null;

		/// <summary>
		/// Label of the token (smartcard) that should be used in these tests. May be null if TokenSerial is specified.
		/// </summary>
		public static string TokenLabel = @"Pkcs11Interop";

		/// <summary>
		/// The normal user pin.
		/// </summary>
		public static string NormalUserPin = @"11111111";
	}
}
