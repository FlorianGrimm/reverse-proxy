// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using System;
using System.Diagnostics.CodeAnalysis;

namespace Yarp.ReverseProxy.Configuration;

public sealed record CertificateConfig : IEquatable<CertificateConfig>
{
    // File

    [MemberNotNullWhen(true, nameof(Path))]
    public bool IsFileCert() => !string.IsNullOrEmpty(Path);

    public string Path { get; init; } = default!;

    public string KeyPath { get; init; } = default!;

    public string Password { get; init; } = default!;


    private bool _fileHasChanged;

    /// <remarks>
    /// Vacuously false if this isn't a file cert.
    /// Used for change tracking - not actually part of configuring the certificate.
    /// </remarks>
    public bool GetFileHasChanged()
    {
        return _fileHasChanged;
    }

    /// <remarks>
    /// Vacuously false if this isn't a file cert.
    /// Used for change tracking - not actually part of configuring the certificate.
    /// </remarks>
    public void SetFileHasChanged(bool value)
    {
        _fileHasChanged = value;
    }

    // Cert store

    [MemberNotNullWhen(true, nameof(Subject))]
    public bool IsStoreCert() => !string.IsNullOrEmpty(Subject);

    public string Subject { get; init; } = default!;

    public string Store { get; init; } = default!;

    public string Location { get; init; } = default!;

    public bool? AllowInvalid { get; init; }

    public bool Equals(CertificateConfig? obj) =>
        obj is CertificateConfig other &&
        Path == other.Path &&
        KeyPath == other.KeyPath &&
        Password == other.Password &&
        GetFileHasChanged() == other.GetFileHasChanged() &&
        Subject == other.Subject &&
        Store == other.Store &&
        Location == other.Location &&
        (AllowInvalid ?? false) == (other.AllowInvalid ?? false);

    public override int GetHashCode() => HashCode.Combine(Path, KeyPath, Password, GetFileHasChanged(), Subject, Store, Location, AllowInvalid ?? false);
}
