# Corely.Security
Corely.Security gives you small plug-in style building blocks for application "lock and key" needs. You ask a factory for a provider (hashing, encryption, signatures). That provider uses a key (from a key provider) fetched through a versioned key store so you can rotate keys later. Hashes and encrypted values come back self-describing (they start with the provider name, and for encryption a key version) so the library can figure out how to verify or decrypt them later without you tracking metadata; signatures are returned bare. You can plug in custom providers or real key management backends, and everything wires cleanly through dependency injection.


> **Upgrading from 1.x?** See [MIGRATION-2.0.md](MIGRATION-2.0.md). Key material moved from
> Base64 `string` to `byte[]`/`ReadOnlySpan<byte>`, and custom providers now pass their name to
> the base constructor. Data written by 1.x stays readable.

## Installation
`dotnet add package Corely.Security`

## Documentation
Details about using this library can be found in the [documentation](https://github.com/ultrabstrong/Corely.Security/blob/master/Docs/index.md).

## Repository
[Corely.Security](https://github.com/ultrabstrong/Corely.Security)

## Contributing
We welcome contributions! Please read our [contributing guidelines](CONTRIBUTING.md) to get started.

## License
This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
