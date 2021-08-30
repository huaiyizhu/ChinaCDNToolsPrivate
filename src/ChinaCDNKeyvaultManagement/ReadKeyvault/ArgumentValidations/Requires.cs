//------------------------------------------------------------------------------
// <copyright file="Requires.cs" company="Microsoft">
//     Copyright (c) Microsoft Corporation.  All rights reserved.
// </copyright>
//------------------------------------------------------------------------------
[assembly: System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.StyleCop.CSharp.DocumentationRules", "SA1600:ElementsMustBeDocumented", Justification = "Reviewed.Suppression is OK here.")]

namespace Microsoft.Cloud.MooncakeService.Common
{
    using System;

    /// <summary>
    /// Argument checking utility.
    /// </summary>
    public static partial class Requires
    {
        /// <summary>
        /// Checks argument value.
        /// </summary>
        /// <typeparam name="T">Type of argument.</typeparam>
        /// <param name="name">Name of argument.</param>
        /// <param name="value">Value of argument.</param>
        /// <returns>The <see cref="ArgumentRequirements"/> for this argument.</returns>
        public static ArgumentRequirements<T> Argument<T>(
            string name,
            [ValidatedNotNull]
            T value)
        {
            return new ArgumentRequirements<T>(name, value);
        }

        /// <summary>
        /// Checks argument value.
        /// </summary>
        /// <typeparam name="T">Type of argument.</typeparam>
        /// <param name="value">Value of argument.</param>
        /// <returns>
        /// The <see cref="ArgumentRequirements" /> for this argument.
        /// </returns>
        public static ArgumentRequirements<T> Argument<T>(
            [ValidatedNotNull]
            T value)
        {
            return new ArgumentRequirements<T>(nameof(value), value);
        }

        /// <summary>
        /// Properties the specified class type.
        /// </summary>
        /// <typeparam name="TProperty">Type of property.</typeparam>
        /// <param name="classType">Type of the class.</param>
        /// <param name="propertyName">Name of the property.</param>
        /// <param name="value">The property value.</param>
        /// <returns>The <see cref="PropertyRequirements"/> for this argument. </returns>
        public static PropertyRequirements<TProperty> Property<TProperty>(Type classType, string propertyName, TProperty value)
        {
            return new PropertyRequirements<TProperty>(classType, propertyName, value);
        }

        /// <summary>
        /// Properties the specified property name.
        /// </summary>
        /// <typeparam name="TProperty">The type of the property.</typeparam>
        /// <typeparam name="TClass">The type of the class.</typeparam>
        /// <param name="classValue">The class value.</param>
        /// <param name="propertyName">Name of the property.</param>
        /// <param name="propertyValue">The property value.</param>
        /// <returns>The <see cref="PropertyRequirements"/> for this argument. </returns>
        public static PropertyRequirements<TProperty> Property<TProperty, TClass>(TClass classValue, string propertyName, TProperty propertyValue)
        {
            return new PropertyRequirements<TProperty>(typeof(TClass), propertyName, propertyValue);
        }

        /// <summary>
        /// Properties the specified property name.
        /// </summary>
        /// <typeparam name="TClass">The type of the class.</typeparam>
        /// <typeparam name="TProperty">The type of the property.</typeparam>
        /// <param name="propertyName">Name of the property.</param>
        /// <param name="value">The property value.</param>
        /// <returns>The <see cref="PropertyRequirements"/> for this argument. </returns>
        public static PropertyRequirements<TProperty> Property<TClass, TProperty>(string propertyName, TProperty value)
        {
            return new PropertyRequirements<TProperty>(typeof(TClass), propertyName, value);
        }
    }
}
