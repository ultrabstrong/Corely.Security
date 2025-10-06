# Corely.Security
Corely.Security gives you small plug-in style building blocks for application "lock and key" needs. You ask a factory for a provider (hashing, encryption, signatures). That provider uses a key (from a key provider) fetched through a versioned key store so you can rotate keys later. The provider returns a self-describing string (it starts with a short code, sometimes also a key version) so the library can figure out how to verify or decrypt it later without you tracking metadata. You can plug in custom providers or real key management backends, and everything wires cleanly through dependency injection.

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
