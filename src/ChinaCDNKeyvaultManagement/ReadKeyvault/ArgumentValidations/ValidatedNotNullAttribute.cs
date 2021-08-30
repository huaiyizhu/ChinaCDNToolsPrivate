//------------------------------------------------------------------------------
// <copyright file="ValidatedNotNullAttribute.cs" company="Microsoft">
//     Copyright (c) Microsoft Corporation.  All rights reserved.
// </copyright>
//------------------------------------------------------------------------------
[assembly: System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.StyleCop.CSharp.DocumentationRules", "SA1600:ElementsMustBeDocumented", Justification = "Reviewed.Suppression is OK here.")]

namespace Microsoft.Cloud.MooncakeService.Common
{
    using System;

    /// <summary>
    /// Workaround attribute to signal the static analysis that we're checking the parameter.
    /// </summary>
    /// <remarks>
    /// Reference:. <seealso cref="https://esmithy.net/2011/03/15/suppressing-ca1062/"/>
    /// </remarks>
    [AttributeUsage(AttributeTargets.Parameter, AllowMultiple = false, Inherited = true)]
    public sealed class ValidatedNotNullAttribute : Attribute
    {
    }
}
