// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using System;
using System.Diagnostics.CodeAnalysis;

namespace Yarp.ReverseProxy.Configuration;

public sealed record CertificateConfig : IEquatable<CertificateConfig>
{
    // File

    [MemberNotNullWhen(true, nameof(Path))]
    public bool IsFileCert => !string.IsNullOrEmpty(Path);

    public string? Path { get; init; }

    public string? KeyPath { get; init; }

    public string? Password { get; init; }

    /// <remarks>
    /// Vacuously false if this isn't a file cert.
    /// Used for change tracking - not actually part of configuring the certificate.
    /// </remarks>
    public bool FileHasChanged { get; internal set; }

    // Cert store

    [MemberNotNullWhen(true, nameof(Subject))]
    public bool IsStoreCert => !string.IsNullOrEmpty(Subject);

    public string? Subject { get; init; }

    public string? Store { get; init; }

    public string? Location { get; init; }

    public bool? AllowInvalid { get; init; }

    public bool Equals(CertificateConfig? obj) =>
        obj is CertificateConfig other &&
        Path == other.Path &&
        KeyPath == other.KeyPath &&
        Password == other.Password &&
        FileHasChanged == other.FileHasChanged &&
        Subject == other.Subject &&
        Store == other.Store &&
        Location == other.Location &&
        (AllowInvalid ?? false) == (other.AllowInvalid ?? false);

    public override int GetHashCode() => HashCode.Combine(Path, KeyPath, Password, FileHasChanged, Subject, Store, Location, AllowInvalid ?? false);
}
