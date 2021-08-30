//------------------------------------------------------------------------------
// <copyright file="ArgumentRequirements.cs" company="Microsoft">
//     Copyright (c) Microsoft Corporation.  All rights reserved.
// </copyright>
//------------------------------------------------------------------------------
[assembly: System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.StyleCop.CSharp.DocumentationRules", "SA1600:ElementsMustBeDocumented", Justification = "Reviewed.Suppression is OK here.")]

namespace Microsoft.Cloud.MooncakeService.Common
{
    using System;
    using System.Globalization;

    /// <summary>
    /// Class for argument requirements.
    /// </summary>
    /// <typeparam name="T">argument type.</typeparam>
    public class ArgumentRequirements<T>
    {
        private readonly string name;
        private readonly T value;

        /// <summary>
        /// Initializes a new instance of the <see cref="ArgumentRequirements{T}"/> class.
        /// </summary>
        /// <param name="name">The name.</param>
        /// <param name="value">The value.</param>
        public ArgumentRequirements(string name, T value)
        {
            this.name = name;
            this.value = value;
        }

        public T Value => value;

        /// <summary>
        /// Checks argument value for not null.
        /// </summary>
        /// <returns>The not null requirement.</returns>
        public ArgumentRequirements<T> NotNull()
        {
            if (this.value == null)
            {
                throw new ArgumentNullException(this.name, string.Format(CultureInfo.InvariantCulture, "Argument {0} cannot be null", this.name));
            }

            return this;
        }

        /// <summary>
        /// Nots the null.
        /// </summary>
        /// <typeparam name="TException">The type of the exception.</typeparam>
        /// <param name="errorMessage">The error message.</param>
        /// <returns>The not null requirement.</returns>
        public ArgumentRequirements<T> NotNull<TException>(string errorMessage) where TException : Exception
        {
            if (this.value == null)
            {
                TException exception = (TException)Activator.CreateInstance(typeof(TException), errorMessage);
                throw exception;
            }

            return this;
        }

        /// <summary>
        /// Checks argument value for not null or empty.
        /// </summary>
        /// <returns>The not null or empty requirement.</returns>
        public ArgumentRequirements<T> NotNullOrEmpty(string errorMessage = null)
        {
            this.NotNull();

            if (typeof(T) == typeof(string))
            {
                string stringValue = this.value as string;
                if (string.IsNullOrWhiteSpace(stringValue))
                {
                    throw new ArgumentException(string.Format(CultureInfo.InvariantCulture, "Argument '{0}' cannot be empty. {1}", this.name, errorMessage), this.name);
                }
            }

            return this;
        }

        /// <summary>
        /// Checks argument value for is undefined enumeration value.
        /// </summary>
        /// <returns>the is undefined enum requirement.</returns>
        /// <exception cref="InvalidOperationException">
        /// Thrown if the given argument type is not an enum type.
        /// </exception>
        /// <exception cref="ArgumentException">
        /// Thrown if the given argument value is not a defined enum value.
        /// </exception>
        public ArgumentRequirements<T> ThrownIfUndefinedEnum()
        {
            Type enumType = typeof(T);
            if (!enumType.IsEnum)
            {
                throw new InvalidOperationException(
                    $"The given value '{this.value}' for argument '{this.name}' is not an enum type value.");
            }

            if (!Enum.IsDefined(enumType, this.value))
            {
                throw new ArgumentException(
                    $"The given value '{this.value}' for argument '{this.name}' is not a defined enum value.",
                    this.name);
            }

            return this;
        }

        /// <summary>
        /// Checks argument value for is undefined or given default enumeration value.
        /// </summary>
        /// <param name="defaultValue">The default enumeration value.</param>
        /// <returns>the is undefined or default enum requirement.</returns>
        /// <exception cref="ArgumentException">
        /// Thrown if the given argument value is a undefined or default enum value.
        /// </exception>
        public ArgumentRequirements<T> ThrownIfUndefinedOrDefaultEnum(T defaultValue)
        {
            this.ThrownIfUndefinedEnum();

            if (this.value.Equals(defaultValue))
            {
                throw new ArgumentException(
                   $"The given value '{this.value}' for argument '{this.name}' cannot be the default value '{defaultValue}'.",
                   this.name);
            }

            return this;
        }

        /// <summary>
        /// Passes the prediction.
        /// </summary>
        /// <param name="predicate">The predicate.</param>
        /// <param name="predicateMessage">The predicate message.</param>
        /// <returns>the valid argument.</returns>
        public ArgumentRequirements<T> PassPredication(Predicate<T> predicate, string predicateMessage)
        {
            if (!predicate.Invoke(this.value))
            {
                throw new ArgumentException(
                    string.Format(CultureInfo.InvariantCulture, "Argument {0} with value \"{1}\" does not meet predication: {2}", this.name, this.value, predicateMessage),
                    this.name);
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
        public ArgumentRequirements<T> ThrowIfNotMatched<TException>(Predicate<T> predicate, Func<TException> exceptionCreator) where TException : Exception
        {
            if (!predicate.Invoke(this.value))
            {
                throw exceptionCreator();
            }

            return this;
        }

        /// <summary>
        /// Throws if not matched.
        /// </summary>
        /// <typeparam name="TException">The type of the exception.</typeparam>
        /// <param name="predicate">The predicate.</param>
        /// <param name="errorMessage">The error message.</param>
        /// <returns>the valid argument.</returns>
        public ArgumentRequirements<T> ThrowIfNotMatched<TException>(Predicate<T> predicate, string errorMessage) where TException : Exception
        {
            if (!predicate.Invoke(this.value))
            {
                TException exception = (TException)Activator.CreateInstance(typeof(TException), errorMessage);
                throw exception;
            }

            return this;
        }

        /// <summary>
        /// Throws if matched.
        /// </summary>
        /// <typeparam name="TException">The type of the exception.</typeparam>
        /// <param name="predicate">The predicate.</param>
        /// <param name="exceptionCreator">The exception creator.</param>
        /// <returns>the valid argument.</returns>
        public ArgumentRequirements<T> ThrowIfMatched<TException>(Predicate<T> predicate, Func<TException> exceptionCreator) where TException : Exception
        {
            if (predicate.Invoke(this.value))
            {
                throw exceptionCreator();
            }

            return this;
        }
    }
}
