# rinpack

`rinpack` is the native RinOS package builder.

It creates `.rpk` packages from RinOS applications, libraries, drivers,
resources, manifests, and package metadata. It does not compile or link
`.rin`, `.rll`, or `.drv` images; those are produced by `rcc`/`rcc++` and
`rld`.

A package may contain signed `.rin`, `.rll`, and `.drv` artifacts together
with resources and package metadata. `rinpack` validates the canonical
`package.toml` manifest, sorts package paths, writes a dense payload, emits
the authenticated RPM1/RFIM policy metadata, and can sign the complete RPKG
image with an RSA publisher identity.

Create an unsigned development package:

```text
rinpack create \
  --manifest package.toml \
  --output app.rpk
```

Create a production package:

```text
rinpack create \
  --manifest package.toml \
  --output app.rpk \
  --sign-key publisher.pem \
  --public-key publisher.der \
  --publisher-generation 1
```

`rinpack inspect --package app.rpk --json` reads the package without
modifying it. `rinpack verify --package app.rpk --public-key publisher.der`
validates the complete package layout and RSA signature.
