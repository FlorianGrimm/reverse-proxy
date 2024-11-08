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

    // Cert store

    [MemberNotNullWhen(true, nameof(Subject))]
    public bool IsStoreCert() => !string.IsNullOrEmpty(Subject);

    public string Subject { get; init; } = default!;

    public string StoreName { get; init; } = default!;

    public string StoreLocation { get; init; } = default!;

    public bool? AllowInvalid { get; init; }

    public bool Equals(CertificateConfig? obj) =>
        obj is CertificateConfig other &&
        Path == other.Path &&
        KeyPath == other.KeyPath &&
        Password == other.Password &&
        Subject == other.Subject &&
        StoreName == other.StoreName &&
        StoreLocation == other.StoreLocation &&
        (AllowInvalid ?? false) == (other.AllowInvalid ?? false);

    public override int GetHashCode() => HashCode.Combine(Path, KeyPath, Password, Subject, StoreName, StoreLocation, AllowInvalid ?? false);
}
