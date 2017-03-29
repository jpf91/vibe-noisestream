vibe-noisestream
================

This implements an ecryption socket based on the [Noise Protocol Framtwork](https://noiseprotocol.org/)
for [vibe.D](http://vibed.org/). The [noise-c](https://github.com/rweather/noise-c)
library is used to implement the `Noise_XX_25519_ChaChaPoly_BLAKE2b` protocol.
[libsodium](http://libsodium.org) is used for secure key memory management.

Note: This project will switch to the NoiseSocket protocol once that has been
formalized.

Note 2: Currently targets vibe.D < 0.7.x.

The API documentation is available [here](https://jpf91.github.io/vibe-noisestream/vibe/noise.html).

A simple server/client example:

```d
import vibe.d, vibe.noise;

void main()
{
    createKeys("server.key", "server.pub");
    createKeys("client.key", "client.pub");

    server();
    runTask(&client);
    runEventLoop();
}

void client()
{
    auto stream = connectTCP("127.0.0.1", 4000);
    auto settings = NoiseSettings(NoiseKind.client);
    settings.privateKeyPath = Path("client.key");
    settings.remoteKeyPath = Path("server.pub");

    auto cryptStream = stream.createNoiseStream(settings);

    // Now use cryptStream as usual
}

void server()
{
    void onConnection(TCPConnection conn)
    {
        auto settings = NoiseSettings(NoiseKind.server);
        settings.privateKeyPath = Path("server.key");
        settings.verifyRemoteKey = (scope const(ubyte[]) remKey) {
            ubyte[KeyLength] pubKey;
            readPublicKey("client.pub", pubKey); 
            return remKey[] == pubKey[];
        };

        auto stream = conn.createNoiseStream(settings);

        // Now read/write data
    }

    listenTCP(4000, &onConnection);
}

```

Known limitations:
------------------
This implements a simple noise protocol without rekeying. This means
after `2^64-1` messages a socket can no longer be used to send messages 
(an Exception will be thrown instead). This also means that long-running
connections keep using the same key. If this temporary key gets compromised
an attacker could decrypt the complete session.
