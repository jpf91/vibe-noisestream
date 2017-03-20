/**
 * 
 */
module vibe.noise;

import vibe.core.stream, vibe.core.file;
import std.array : empty;
import std.exception : enforceEx;
import std.algorithm : min;
import deimos.sodium;
import noise;

/**
 * Exception thrown on internal errors.
 */
class NoiseException : Exception
{
public:
    @trusted pure nothrow this(string message, int error, string file = __FILE__,
        size_t line = __LINE__, Throwable next = null)
    {
        import core.stdc.string : strlen;

        char[128] msgBuf;
        noise_strerror(error, msgBuf.ptr, msgBuf.length);
        char[] errMsg = msgBuf[0 .. strlen(msgBuf.ptr)];
        super(message ~ errMsg.idup, file, line, next);
    }

    @safe pure nothrow this(string message, string file = __FILE__,
        size_t line = __LINE__, Throwable next = null)
    {
        super(message, file, line, next);
    }
}

/**
 * Exception thrown when authentication in createNoiseStream failed.
 */
class AuthException : Exception
{
public:
    @safe pure nothrow this(string message, string file = __FILE__,
        size_t line = __LINE__, Throwable next = null)
    {
        super(message, file, line, next);
    }
}

/// Key size of public and private keys.
enum KeySize = 32;

/**
 * Create a public/private keypair to be used with createNoiseStream.
 *
 * Warning: When using the overload taking two `ubyte[]` buffers,
 * the privKey buffer needs to be a secure buffer. Avoid copying this
 * data around and make sure to (properly!) zero the data if you no longer need it.
 * Also guarding the key memory page as done by libsodium is recommended.
 *
 * The overloads not taking a privateKey `ubyte[]` buffer handle all these details.
 */
void createKeys(string privKeyFile, string pubKeyFile)
{
    createKeys(Path(privKeyFile), Path(pubKeyFile));
}

/// ditto
void createKeys(Path privKeyFile, Path pubKeyFile)
{
    // 1*keys, then 2*keySize+1 for hex encoding
    enum BufLength = KeySize + KeySize * 2 + 1;
    auto keyPtr = sodium_malloc(BufLength);
    noiseEnforce(keyPtr !is null, "Failed to allocate memory");
    scope (exit)
        sodium_free(keyPtr);

    auto pubKey = cast(ubyte[]) keyPtr[0 .. KeySize];
    auto pubKeyHex = cast(char[]) keyPtr[KeySize .. BufLength];

    createKeys(privKeyFile, pubKey);
    pubKeyHex = keyToHex(pubKey, pubKeyHex);

    writeFileUTF8(pubKeyFile, cast(string) pubKeyHex);
}

/// ditto
void createKeys(string privKeyFile, ubyte[] pubKey)
{
    createKeys(Path(privKeyFile), pubKey);
}

/// ditto
void createKeys(Path privKeyFile, ubyte[] pubKey)
{
    auto keyPtr = sodium_malloc(KeySize);
    noiseEnforce(keyPtr !is null, "Failed to allocate memory");
    scope (exit)
        sodium_free(keyPtr);

    auto privKey = cast(ubyte[]) keyPtr[0 .. KeySize];
    createKeys(privKey, pubKey);
    writeFile(privKeyFile, privKey);
}

/// ditto
void createKeys(ubyte[] privKey, ubyte[] pubKey)
{
    noiseEnforce(sodiumResult != -1, "Failed to initialize libsodium");
    noiseEnforce(privKey.length == KeySize && pubKey.length == KeySize,
        "Buffers for keys must be 32 byte long");

    NoiseDHState* dh;
    // Generate a keypair
    noiseCheck(noise_dhstate_new_by_id(&dh, NOISE_DH_CURVE25519));
    scope (exit)
        noise_dhstate_free(dh);

    noiseCheck(noise_dhstate_generate_keypair(dh));
    noiseCheck(noise_dhstate_get_keypair(dh, privKey.ptr, privKey.length,
        pubKey.ptr, pubKey.length));
}

// Test invalid buffer lengths
unittest
{
    ubyte[31] sBuf;
    ubyte[32] buf;
    ubyte[33] lBuf;

    assertThrown(createKeys(buf[], sBuf[]));
    assertThrown(createKeys(buf[], lBuf[]));
    assertThrown(createKeys(sBuf[], buf[]));
    assertThrown(createKeys(lBuf[], buf[]));
}

/**
 * Convert key from binary to hex format.
 *
 * Note: The KeyHex buffer needs to be 2*KeySize+1 bytes long as
 * the function will internally write a `\0` at the end of the buffer.
 * The return value returns a slice with adjusted length to exclude this trailing
 * `\0`.
 */
char[] keyToHex(ubyte[] keyBin, char[] keyHex)
{
    noiseEnforce(keyBin.length == KeySize && keyHex.length == 2 * KeySize + 1,
        "Invalid input buffer size");
    noiseEnforce(sodium_bin2hex(keyHex.ptr, keyHex.length, keyBin.ptr, keyBin.length) !is null);
    return keyHex[0 .. $ - 1];
}

// Test invalid buffer lengths
unittest
{
    ubyte[31] sBuf;
    ubyte[32] buf;
    char[64 + 1] hBuf;

    assertThrown(keyToHex(buf[], cast(char[]) sBuf[]));
    assertThrown(keyToHex(sBuf[], hBuf[]));
}

/**
 * Convert key from hex to binary format.
 *
 * Note: keyHex.length needs to be 2*KeySize.
 */
void keyFromHex(char[] keyHex, ubyte[] keyBin)
{
    noiseEnforce(keyBin.length == KeySize && keyHex.length == 2 * KeySize,
        "Invalid input buffer size");

    size_t readLength = 0;
    auto result = sodium_hex2bin(keyBin.ptr, keyBin.length, keyHex.ptr,
        keyHex.length, null, &readLength, null);

    noiseEnforce(result == 0 && readLength == 32, "Invalid public key input");
}

/**
 * Reads a public key file writen by createKeys.
 */
void readPublicKey(string file, ubyte[] data)
{
    readPublicKey(Path(file), data);
}

/// ditto
void readPublicKey(Path file, ubyte[] data)
{
    noiseEnforce(data.length == 32, "Key buffer needs to be 32 byte long");

    // 3 bytes BOM, 2 * keySize for hex encoding, allow up to 4 trailing bytes
    // (CRLF CRLF)
    ubyte[3 + 2 * 32 + 4] hexBuf;
    scope (exit)
        sodium_memzero(hexBuf.ptr, hexBuf.length);

    ubyte[] hexRead;
    // If file is too large, report error
    try
        hexRead = file.readFile(hexBuf[], hexBuf.length);
    catch (Exception e)
        noiseEnforce(false, "Invalid public key file");

    // Remove BOM
    if (hexRead.length >= 3 && hexRead[0 .. 3] == [0xEF, 0xBB, 0xBF])
    {
        hexRead = hexRead[3 .. $];
    }

    // Need at least 64 bytes
    noiseEnforce(hexRead.length >= 64, "Invalid public key file");

    // Convert to binary
    keyFromHex(cast(char[]) hexRead[0 .. 2 * KeySize], data);
}

// Test whether readPublicKey reads data correctly
unittest
{
    import std.file;

    string privFile = "private.key";
    string pubFile = "public.key";
    scope (exit)
    {
        if (privFile.exists)
            remove(privFile);
        if (pubFile.exists)
            remove(pubFile);
    }

    // Create & write key
    ubyte[KeySize] pubKey;
    char[2 * KeySize + 1] pubKeyHex;
    createKeys(privFile, pubKey[]);
    writeFileUTF8(Path(pubFile), cast(string) keyToHex(pubKey, pubKeyHex[]));

    // Read & verify key
    ubyte[32] readKey;
    readPublicKey(pubFile, readKey[]);
    assert(readKey[] == pubKey);

    // Trailing new line
    writeFileUTF8(Path(pubFile), (cast(string) keyToHex(pubKey, pubKeyHex[])) ~ "\r\n");
    readPublicKey(pubFile, readKey[]);
    assert(readKey[] == pubKey);

    // No BOM
    writeFile(Path(pubFile), cast(ubyte[]) keyToHex(pubKey, pubKeyHex[]));
    readPublicKey(pubFile, readKey[]);
    assert(readKey[] == pubKey);

    // No BOM + trailing newline
    writeFile(Path(pubFile), cast(ubyte[])(keyToHex(pubKey, pubKeyHex[]) ~ ['\r', '\n']));
    readPublicKey(pubFile, readKey[]);
    assert(readKey[] == pubKey);
}

// Test whether readPublicKey reads file generated by createKeys
unittest
{
    import std.file;

    string privFile = "private.key";
    string pubFile = "public.key";
    scope (exit)
    {
        if (privFile.exists)
            remove(privFile);
        if (pubFile.exists)
            remove(pubFile);
    }

    // Create & write key
    ubyte[32] readKey;
    createKeys(privFile, pubFile);
    readPublicKey(pubFile, readKey[]);

    // Test short buffer
    assertThrown(readPublicKey(pubFile, readKey[0 .. 31]));
}

// Read invalid files
unittest
{
    import std.file;

    string privFile = "private.key";
    string pubFile = "public.key";
    scope (exit)
    {
        if (privFile.exists)
            remove(privFile);
        if (pubFile.exists)
            remove(pubFile);
    }

    ubyte[KeySize] key;
    // too short
    writeFileUTF8(Path(pubFile), "aabb00");
    assertThrown(readPublicKey(pubFile, key[]));

    // too long
    writeFileUTF8(Path(pubFile),
        "aabb00aabb00aabb00aaaabb00aabb00aabb00aaaabb00" ~ "aabb00aabb00aaaabb00aabb00aabb00aaaabb00aabb00aabb00aaaabb00aabb0" ~ "0aabb00aaaabb00aabb00aabb00aaaabb00aabb00aabb00aa");
    assertThrown(readPublicKey(pubFile, key[]));

    // invalid data
    writeFileUTF8(Path(pubFile),
        "xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" ~ "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
    assertThrown(readPublicKey(pubFile, key[]));

    // non-existent file
    remove(pubFile);
    assertThrown(readPublicKey(pubFile, key[]));
}

/**
 * Kind of NoiseStream.
 */
enum NoiseKind
{
    ///
    server,
    ///
    client
}

/**
 * Provide a delegate of this types to verify the public key of the node
 * connected to.
 */
alias VerifyKeyDelegate = scope nothrow bool delegate(scope const(ubyte[]));

/**
 * Settings for the connectNoiseStream function.
 */
struct NoiseSettings
{
    /// Client or server role.
    NoiseKind kind;
    /**
     * Path to private key file. Either this or the privateKey field
     * must be set. If both are set the privateKeyPath field is used.
     */
    Path privateKeyPath;

    /**
     * Private key in memory.
     *
     * Warning: When using this overload, make sure to use secure memory.
     * The memory should be cleared after the createNoiseStream call returns.
     *
     * The privateKeyPath allows for a simpler, secure API.
     */
    const(ubyte)[] privateKey;

    /**
     * If provided will be used to verify the remote public key.
     * If this is not set remoteKeyPath is used instead.
     */
    VerifyKeyDelegate verifyRemoteKey;

    /**
     * Path to public key file of remote server
     */
    Path remoteKeyPath;

    /**
     * Convenience constructor.
     */
    public this(NoiseKind kind)
    {
        this.kind = kind;
    }
}

/**
 * Create a noise encrypted stream on top of a normal stream.
 * 
 * Throws: NoiseException on internal error, AuthException if authentication failed.
 * Exceptions thrown from the low-level stream get passed through.
 */
NoiseStream createNoiseStream(Stream stream, scope NoiseSettings settings)
{
    auto cstream = new NoiseStream(stream);
    cstream.handshake(settings);
    return cstream;
}

/**
 * Wraps a normal Stream to add encryption based on the
 * Noise_XX_25519_ChaChaPoly_BLAKE2b protocol.
 */
class NoiseStream : Stream
{
private:
    enum NoiseProtocolID = "Noise_XX_25519_ChaChaPoly_BLAKE2b";
    NoiseCipherState* _writeCipher, _readCipher;
    Stream _stream;
    bool _finalized;
    // Read buffer contains encrypted or decrypted data
    ubyte[2048] _readBuf;
    // Slice into _readBuf with remaining decrypted data
    ubyte[] _readDecrypted;
    // Buffer used for writing only
    ubyte[2048] _writeBuf;

    this(Stream stream) pure nothrow @safe @nogc
    {
        this._stream = stream;
    }

    size_t readPacket()
    {
        ubyte[2] message_size;
        _stream.read(message_size[]);
        ushort len = (message_size[0] << 8) | message_size[1];
        noiseEnforce(len < _readBuf.length, "Ivalid packet length");
        _stream.read(_readBuf[0 .. len]);
        return len;
    }

    void readAndDecrypt()
    {
        NoiseBuffer mbuf;
        while (_readDecrypted.empty)
        {
            auto len = readPacket();
            noise_buffer_set_input(mbuf, _readBuf.ptr, len);
            noiseCheck(noise_cipherstate_decrypt(_readCipher, &mbuf));
            _readDecrypted = _readBuf[0 .. mbuf.size];
        }
    }

    void handshake(scope NoiseSettings settings)
    {
        NoiseHandshakeState* handshake;

        // Check library initialization
        noiseCheck(initResult, "Failed to initialize libnoise-c");
        noiseEnforce(sodiumResult != -1, "Failed to initialize libsodium");
        // Check settings
        noiseEnforce(!settings.privateKeyPath.empty
            || !settings.privateKey.empty, "Need either privateKeyPath or privateKey");
        noiseEnforce(settings.verifyRemoteKey !is null
            || !settings.remoteKeyPath.empty, "Need either remoteKeyPath or verifyRemoteKey");

        auto role = settings.kind == NoiseKind.client ? NOISE_ROLE_INITIATOR : NOISE_ROLE_RESPONDER;
        noiseCheck(noise_handshakestate_new_by_name(&handshake, NoiseProtocolID.ptr,
            role));
        scope (exit)
            noise_handshakestate_free(handshake);

        // 2*keys
        enum BufLength = KeySize * 2;
        auto keyPtr = sodium_malloc(BufLength);
        noiseEnforce(keyPtr !is null, "Failed to allocate memory");
        scope (exit)
            sodium_free(keyPtr);

        auto privKey = cast(ubyte[]) keyPtr[0 .. KeySize];
        auto pubKey = cast(ubyte[]) keyPtr[KeySize .. 2 * KeySize];

        // Set private key
        auto dh = noise_handshakestate_get_local_keypair_dh(handshake);
        if (settings.privateKeyPath.empty)
        {
            auto key_len = noise_dhstate_get_private_key_length(dh);
            noiseEnforce(key_len == settings.privateKey.length, "Invalid length for private key");
            noiseCheck(noise_dhstate_set_keypair_private(dh, settings.privateKey.ptr,
                key_len));
        }
        else
        {
            settings.privateKeyPath.readFile(privKey, privKey.length);
            noiseCheck(noise_dhstate_set_keypair_private(dh, privKey.ptr, privKey.length));
        }

        // Start handshaking
        NoiseBuffer mbuf;
        noiseCheck(noise_handshakestate_start(handshake));
        while (true)
        {
            auto action = noise_handshakestate_get_action(handshake);

            if (action == NOISE_ACTION_WRITE_MESSAGE)
            {
                /* Write the next handshake message with a zero-length payload */
                noise_buffer_set_output(mbuf, &_writeBuf[2], _writeBuf.length - 2);
                noiseCheck(noise_handshakestate_write_message(handshake, &mbuf, null));
                _writeBuf[0] = cast(ubyte)(mbuf.size >> 8);
                _writeBuf[1] = cast(ubyte) mbuf.size;

                _stream.write(_writeBuf[0 .. mbuf.size + 2]);
                _stream.flush();
            }
            else if (action == NOISE_ACTION_READ_MESSAGE)
            {
                /* Read the next handshake message and discard the payload */
                auto len = readPacket();
                noise_buffer_set_input(mbuf, _readBuf.ptr, len);
                noiseCheck(noise_handshakestate_read_message(handshake, &mbuf, null));
            }
            else
            {
                break;
            }
        }
        noiseEnforce(noise_handshakestate_get_action(handshake) == NOISE_ACTION_SPLIT);

        // Verify public key
        auto reDHState = noise_handshakestate_get_remote_public_key_dh(handshake);
        ubyte[KeySize] recPublicKey;
        noiseCheck(noise_dhstate_get_public_key(reDHState, recPublicKey.ptr, recPublicKey.length));
        scope (exit)
            sodium_memzero(recPublicKey.ptr, recPublicKey.length);

        if (settings.verifyRemoteKey is null)
        {
            readPublicKey(settings.remoteKeyPath, pubKey);
            enforceEx!AuthException(recPublicKey[] == pubKey[],
                "Authentication failed: Public keys not equal");
        }
        else
        {
            enforceEx!AuthException(settings.verifyRemoteKey(recPublicKey),
                "Authentication failed: Verificaition callback returned false");
        }

        noiseCheck(noise_handshakestate_split(handshake, &_writeCipher, &_readCipher));
    }

public:
    /**
     * Returns true $(I iff) the end of the input stream has been reached.
     */
    @property bool empty()
    {
        return _readDecrypted.empty && _stream.empty;
    }

    /**
     * Returns the maximum number of bytes that are known to remain in this stream until the
     * end is reached. After leastSize() bytes have been read, the stream will either have
     * reached EOS and empty() returns true, or leastSize() returns again a number > 0.
     */
    @property ulong leastSize()
    {
        if (!_readDecrypted.empty)
            return _readDecrypted.length;
        else
        {
            if (empty)
                return 0;

            readAndDecrypt();
            return _readDecrypted.length;
        }
    }

    /**
     * Queries if there is data available for immediate, non-blocking read.
     */
    @property bool dataAvailableForRead()
    {
        // Do not check _stream.dataAvailableForRead: We do not know
        // if we could read enough data to decrypt the next packet but if we
        // can't decrypt, we have to block. Could maybe check peek of the
        // underlying stream instead
        return !_readDecrypted.empty;
    }

    /**
     * Returns a temporary reference to the data that is currently buffered.
     * The returned slice typically has the size `leastSize()` or `0` if
     * `dataAvailableForRead()` returns false. Streams that don't have an
     * internal buffer will always return an empty slice.
     * Note that any method invocation on the same stream potentially
     * invalidates the contents of the returned buffer.
     */
    const(ubyte)[] peek()
    {
        return _readDecrypted;
    }

    /**
     * Fills the preallocated array 'bytes' with data from the stream.
     * Throws: An exception if the operation reads past the end of the stream
     */
    void read(ubyte[] dst)
    {
        while (dst.length != 0)
        {
            if (_readDecrypted.empty)
                readAndDecrypt();

            auto incr = min(dst.length, _readDecrypted.length);
            dst[0 .. incr] = _readDecrypted[0 .. incr];
            _readDecrypted = _readDecrypted[incr .. $];
            dst = dst[incr .. $];
        }
    }

    /**
     * Writes an array of bytes to the stream.
     */
    void write(in ubyte[] bytesConst)
    {
        const(ubyte)[] bytes = bytesConst;
        NoiseBuffer mbuf;
        while (bytes.length != 0)
        {
            // 2 bytes for length, 16 bytes for MAC
            enum MaxDataLength = _writeBuf.length - 2 - 16;
            auto nextWrite = min(bytes.length, MaxDataLength);
            _writeBuf[2 .. nextWrite + 2] = bytes[0 .. nextWrite];
            bytes = bytes[nextWrite .. $];

            noise_buffer_set_inout(mbuf, &_writeBuf[2], nextWrite, _writeBuf.length - 2);
            noiseCheck(noise_cipherstate_encrypt(_writeCipher, &mbuf));
            _writeBuf[0] = cast(ubyte)(mbuf.size >> 8);
            _writeBuf[1] = cast(ubyte) mbuf.size;
            _stream.write(_writeBuf[0 .. mbuf.size + 2]);
        }
    }

    /**
     * Flushes the stream and makes sure that all data is being written to the output device.
     */
    void flush()
    {
        _stream.flush();
        // We always create one crypted packet in write
        // TODO: is this a problem for small writes? Is flush for network like
        // streams well supported? Then we could fill the buffer before writing...
    }

    /**
     * Flushes and finalizes the stream.
     * Finalize has to be called on certain types of streams. No writes are possible after a
     * call to finalize().
     */
    void finalize()
    {
        if (!_finalized)
        {
            _finalized = true;
            noiseCheck(noise_cipherstate_free(_writeCipher));
            noiseCheck(noise_cipherstate_free(_readCipher));
        }
    }

    /**
     * Not implemented.
     */
    void write(InputStream stream, ulong nbytes = 0)
    {
        //TODO
        assert(false, "Not implemented");
    }
}

private:
void noiseEnforce(bool condition, string msg = "", string file = __FILE__,
    size_t line = __LINE__, Throwable next = null) @safe
{
    if (!condition)
        throw new NoiseException(msg, file, line, next);
}

void noiseCheck(int code, string msg = "", string file = __FILE__,
    size_t line = __LINE__, Throwable next = null) @safe
{
    if (code != NOISE_ERROR_NONE)
        throw new NoiseException(msg, code, file, line, next);
}

__gshared int initResult;
__gshared int sodiumResult = -1;

shared static this()
{
    initResult = noise_init();
    sodiumResult = sodium_init();
}

version (unittest)
{
    import vibe.d;
    import std.exception, std.stdio;

    short testPort = 4000;

    void testClient()
    {
        try
        {
            sleep(dur!"seconds"(1));
            auto conn = connectTCP("127.0.0.1", testPort);
            auto settings = NoiseSettings(NoiseKind.client);
            settings.privateKeyPath = Path("private.key");
            settings.remoteKeyPath = Path("public.key");
            auto stream = conn.createNoiseStream(settings);

            // Test up to 32kB
            auto wdata = new ubyte[1024 * 32];
            auto rdata = wdata.dup;
            foreach (i, ref entry; wdata)
            {
                entry = i % 256;
            }

            // Write all different data lengths
            for (size_t i = 0; i < wdata.length; i++)
            {
                stream.write(wdata[0 .. i]);
            }

            // Read all different data lengths
            for (size_t i = 0; i < rdata.length; i++)
            {
                stream.read(rdata[0 .. i]);
                assert(rdata[0 .. i] == wdata[0 .. i]);
            }

            // Read/Write all different data lengths
            for (size_t i = 0; i < wdata.length; i += 512)
            {
                stream.write(wdata[0 .. i]);
                stream.read(rdata[0 .. i]);
                assert(rdata[0 .. i] == wdata[0 .. i]);
            }

            // Read & keep some data in buffer, server sent 128 bytes;
            stream.read(rdata[0 .. 64]);
            assert(rdata[0 .. 64] == wdata[0 .. 64]);
            assert(!stream.empty);
            assert(stream.dataAvailableForRead);
            assert(stream.leastSize == 64);
            assert(stream.peek.length == 64 && stream.peek()[0 .. 64] == wdata[64 .. 128]);
            // Now drain the internal buffer exactly
            stream.read(rdata[64 .. 128]);
            assert(rdata[0 .. 128] == wdata[0 .. 128]);
            assert(!stream.empty);
            assert(!stream.dataAvailableForRead);
            assert(stream.peek.length == 0);

            // Now this reads in the next packet
            assert(stream.leastSize == 64);
            // Now read two 64 byte writes as one 128 byte read
            stream.read(rdata[0 .. 128]);
            assert(rdata[0 .. 128] == wdata[0 .. 128]);

            // Now test stream closed behaviour
            assert(stream.empty);
            assert(!stream.dataAvailableForRead);
            assert(stream.leastSize == 0);
            assert(stream.peek().length == 0);
            assertThrown(stream.read(rdata[0 .. 128]));

            stream.finalize();
            conn.close();
            exitEventLoop();
        }
        catch (Exception e)
        {
            writeln(e);
            exitEventLoop();
        }
    }

    struct NoiseServer
    {
        NoiseSettings settings;

        void testServer(TCPConnection conn)
        {
            try
            {
                auto stream = conn.createNoiseStream(settings);

                // Test up to 32kB
                auto wdata = new ubyte[1024 * 32];
                auto rdata = wdata.dup;
                foreach (i, ref entry; wdata)
                {
                    entry = i % 256;
                }

                // Read all different data lengths
                for (size_t i = 0; i < rdata.length; i++)
                {
                    stream.read(rdata[0 .. i]);
                    assert(rdata[0 .. i] == wdata[0 .. i]);
                }

                // Write all different data lengths
                for (size_t i = 0; i < wdata.length; i++)
                {
                    stream.write(wdata[0 .. i]);
                }

                // Write/Read different data lengths
                for (size_t i = 0; i < wdata.length; i += 512)
                {
                    stream.read(rdata[0 .. i]);
                    stream.write(wdata[0 .. i]);
                    assert(rdata[0 .. i] == wdata[0 .. i]);
                }

                // Send 128 bytes;
                stream.write(wdata[0 .. 128]);
                // Send two 64 byte packets
                stream.write(wdata[0 .. 64]);
                stream.write(wdata[64 .. 128]);

                stream.flush();
                stream.finalize();
                conn.close();
            }
            catch (Exception e)
            {
                writeln(e);
                exitEventLoop();
            }
        }
    }
}

// Test key generation
unittest
{
    import std.file;

    string privFile = "private.key";
    string pubFile = "public.key";

    createKeys(privFile, pubFile);
    scope (exit)
    {
        if (privFile.exists)
            remove(privFile);
        if (pubFile.exists)
            remove(pubFile);
    }

    assert(privFile.exists && pubFile.exists);
    auto content = readFileUTF8(pubFile);
    assert(content.length == 64);

    auto privContent = read(privFile);
    assert(privContent.length == 32);
}

// Full test using key files
unittest
{
    import std.file;

    string privFile = "private.key";
    string pubFile = "public.key";

    createKeys(privFile, pubFile);
    scope (exit)
    {
        if (privFile.exists)
            remove(privFile);
        if (pubFile.exists)
            remove(pubFile);
    }

    // Run server
    auto settings = NoiseSettings(NoiseKind.server);
    settings.privateKeyPath = Path(privFile);
    settings.remoteKeyPath = Path(pubFile);
    auto server = NoiseServer(settings);
    listenTCP(testPort, &server.testServer);

    // Run client
    runTask(toDelegate(&testClient));

    runEventLoop();
    testPort++;
}

// Full test using private key file
unittest
{
    import std.file;

    string privFile = "private.key";
    string pubFile = "public.key";

    createKeys(privFile, pubFile);
    scope (exit)
    {
        if (privFile.exists)
            remove(privFile);
        if (pubFile.exists)
            remove(pubFile);
    }

    ubyte[32] pubKey;
    readPublicKey(pubFile, pubKey);

    // Run server
    auto settings = NoiseSettings(NoiseKind.server);
    settings.verifyRemoteKey = (scope const(ubyte[]) remKey) {
        assert(remKey[] == pubKey[]);
        return remKey[] == pubKey[];
    };
    settings.privateKeyPath = Path(privFile);
    auto server = NoiseServer(settings);
    listenTCP(testPort, &server.testServer);
    // Run client
    runTask(toDelegate(&testClient));

    runEventLoop();
    testPort++;
}

// Full test using public key file
unittest
{
    import std.file;

    string privFile = "private.key";
    string pubFile = "public.key";

    createKeys(privFile, pubFile);
    scope (exit)
    {
        if (privFile.exists)
            remove(privFile);
        if (pubFile.exists)
            remove(pubFile);
    }

    // Run server
    auto settings = NoiseSettings(NoiseKind.server);
    settings.privateKey = readFile(privFile);
    settings.remoteKeyPath = Path(pubFile);
    auto server = NoiseServer(settings);
    listenTCP(testPort, &server.testServer);

    // Run client
    runTask(toDelegate(&testClient));

    runEventLoop();
    testPort++;
}

// Full test using no key files
unittest
{
    import std.file, std.typecons;

    string privFile = "private.key";
    string pubFile = "public.key";

    createKeys(privFile, pubFile);
    scope (exit)
    {
        if (privFile.exists)
            remove(privFile);
        if (pubFile.exists)
            remove(pubFile);
    }

    ubyte[32] pubKey;
    readPublicKey(pubFile, pubKey);

    // Run server
    auto settings = NoiseSettings(NoiseKind.server);
    settings.verifyRemoteKey = (scope const(ubyte[]) remKey) {
        assert(remKey[] == pubKey[]);
        return remKey[] == pubKey[];
    };
    settings.privateKey = readFile(privFile);
    auto server = NoiseServer(settings);
    listenTCP(testPort, &server.testServer);

    // Run client
    runTask(toDelegate(&testClient));

    runEventLoop();
    testPort++;
}

// Test invalid settings
unittest
{
    import std.file, std.typecons;

    string privFile = "private.key";
    string pubFile = "public.key";

    createKeys(privFile, pubFile);

    ubyte[32] pubKey;
    readPublicKey(pubFile, pubKey);

    // No private key
    auto settings = NoiseSettings(NoiseKind.server);
    settings.verifyRemoteKey = (scope const(ubyte[]) remKey) {
        assert(remKey[] == pubKey[]);
        return remKey[] == pubKey[];
    };
    assertThrown(createNoiseStream(null, settings));

    // No public key verification
    settings = NoiseSettings(NoiseKind.server);
    settings.privateKey = readFile(privFile);
    assertThrown(createNoiseStream(null, settings));
}
