using System.Diagnostics.CodeAnalysis;

[assembly: SuppressMessage(
    "Style",
    "IDE0290:Use primary constructor",
    Justification = "Primary constructors don't support making params readonly (as of 12-30-23)",
    Scope = "module"
)]
[assembly: SuppressMessage(
    "Style",
    "IDE0130:Namespace does not match folder structure",
    Justification = "Including Symmetric / Asymmetric in namespaces makes them unnecessarily long",
    Scope = "module"
)]
