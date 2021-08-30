//------------------------------------------------------------------------------
// <copyright file="PropertyRequirements.cs" company="Microsoft">
//     Copyright (c) Microsoft Corporation.  All rights reserved.
// </copyright>
//------------------------------------------------------------------------------
[assembly: System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.StyleCop.CSharp.DocumentationRules", "SA1600:ElementsMustBeDocumented", Justification = "Reviewed.Suppression is OK here.")]

namespace Microsoft.Cloud.MooncakeService.Common
{
    using System;
    using System.Globalization;

    /// <summary>
    /// Class for property requirements.
    /// </summary>
    /// <typeparam name="T">property type.</typeparam>
    public class PropertyRequirements<T>
    {
        private Type classType;
        private string propertyName;
        private T value;

        /// <summary>
        /// Initializes a new instance of the <see cref="PropertyRequirements{T}"/> class.
        /// </summary>
        /// <param name="classType">Type of the class.</param>
        /// <param name="propertyName">Name of the property.</param>
        /// <param name="value">The value.</param>
        public PropertyRequirements(Type classType, string propertyName, T value)
        {
            this.classType = classType;
            this.propertyName = propertyName;
            this.value = value;
        }

        /// <summary>
        /// Not the null.
        /// </summary>
        /// <returns>the valid property.</returns>
        /// <exception cref="System.ArgumentNullException">the property is null.</exception>
        public PropertyRequirements<T> NotNull()
        {
            if (this.value == null)
            {
                throw new ArgumentNullException(this.propertyName, string.Format(CultureInfo.InvariantCulture, "Property {0}.{1} cannot be null", this.classType.Name, this.propertyName));
            }

            return this;
        }

        /// <summary>
        /// Not the null or empty.
        /// </summary>
        /// <returns>the valid property.</returns>
        /// <exception cref="System.ArgumentException">the property is null or empty.</exception>
        public PropertyRequirements<T> NotNullOrEmpty()
        {
            this.NotNull();

            string stringValue = this.value as string;
            if (string.IsNullOrWhiteSpace(stringValue))
            {
                throw new ArgumentException(string.Format(CultureInfo.InvariantCulture, "Property '{0}.{1}' cannot be empty", this.classType.Name, this.propertyName), this.propertyName);
            }

            return this;
        }

        /// <summary>
        /// Not the equal to.
        /// </summary>
        /// <param name="checkValue">The check value.</param>
        /// <returns>the valid property.</returns>
        /// <exception cref="System.ArgumentException">the property is equal to the check value.</exception>
        public PropertyRequirements<T> NotEqualTo(T checkValue)
        {
            if (this.value.Equals(checkValue))
            {
                throw new ArgumentException(string.Format(CultureInfo.InvariantCulture, "Property '{0}.{1}' should not equal to {2}", this.classType.Name, this.propertyName, checkValue), this.propertyName);
            }

            return this;
        }

        /// <summary>
        /// Passes the prediction.
        /// </summary>
        /// <param name="predicate">The predicate.</param>
        /// <param name="predicateMessage">The predicate error message.</param>
        /// <returns>the valid property.</returns>
        /// <exception cref="System.ArgumentException">the property cannot pass predication.</exception>
        public PropertyRequirements<T> PassPredication(Predicate<T> predicate, string predicateMessage)
        {
            if (!predicate.Invoke(this.value))
            {
                throw new ArgumentException(
                    string.Format(CultureInfo.InvariantCulture, "Property {0}.{1} with value \"{2}\" does not meet predication: {3}", this.classType.Name, this.propertyName, this.value, predicateMessage),
                    this.propertyName);
            }

            return this;
        }

        /// <summary>
        /// Throw if.
        /// </summary>
        /// <typeparam name="TException">The type of the exception.</typeparam>
        /// <param name="predicate">The predicate.</param>
        /// <param name="exceptionCreator">The exception creator.</param>
        /// <returns>the valid argument.</returns>
        public PropertyRequirements<T> ThrowIfNotMatched<TException>(Predicate<T> predicate, Func<TException> exceptionCreator) where TException : Exception
        {
            if (!predicate.Invoke(this.value))
            {
                throw exceptionCreator();
            }

            return this;
        }
    }
}
