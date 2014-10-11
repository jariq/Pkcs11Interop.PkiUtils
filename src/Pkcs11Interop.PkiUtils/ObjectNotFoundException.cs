/*
 *  Pkcs11Interop.PkiUtils - PKI extensions for Pkcs11Interop library
 *  Copyright (c) 2013-2014 JWC s.r.o. <http://www.jwc.sk>
 *  Author: Jaroslav Imrich <jimrich@jimrich.sk>
 *
 *  Licensing for open source projects:
 *  Pkcs11Interop.PkiUtils is available under the terms of the GNU Affero General 
 *  Public License version 3 as published by the Free Software Foundation.
 *  Please see <http://www.gnu.org/licenses/agpl-3.0.html> for more details.
 *
 *  Licensing for other types of projects:
 *  Pkcs11Interop.PkiUtils is available under the terms of flexible commercial license.
 *  Please contact JWC s.r.o. at <info@pkcs11interop.net> for more details.
 */

using System;

namespace Net.Pkcs11Interop.PkiUtils
{
    /// <summary>
    /// Exception indicating that required object was not found on the token
    /// </summary>
    public class ObjectNotFoundException : Exception
    {
        /// <summary>
        /// Initializes a new instance of the ObjectNotFoundException class
        /// </summary>
        public ObjectNotFoundException()
            : base()
        {

        }

        /// <summary>
        /// Initializes a new instance of the ObjectNotFoundException class with a specified error message
        /// </summary>
        /// <param name="message">The message that describes the error</param>
        public ObjectNotFoundException(string message)
            : base(message)
        {

        }

        /// <summary>
        /// Initializes a new instance of the ObjectNotFoundException class with a specified error message and a reference to the inner exception that is the cause of this exception
        /// </summary>
        /// <param name="message">The error message that explains the reason for the exception</param>
        /// <param name="innerException">The exception that is the cause of the current exception, or a null reference if no inner exception is specified.</param>
        public ObjectNotFoundException(string message, Exception innerException)
            : base(message, innerException)
        {

        }
    }
}
