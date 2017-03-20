/**
 * Contains bindings for some noise functions
 */
module noise;

int NOISE_ID(char ch, int num)
{
    return ((cast(int) ch) << 8) | num;
}

extern (C) pure nothrow @nogc
{
    import core.stdc.stdint;

    struct NoiseHandshakeState
    {
    }

    struct NoiseDHState
    {
    }

    struct NoiseCipherState
    {
    }

    struct NoiseBuffer
    {
        uint8_t* data;
        size_t size;
        size_t max_size;
    }

    int noise_handshakestate_new_by_name(NoiseHandshakeState** state,
        const char* protocol_name, int role);
    int noise_handshakestate_free(NoiseHandshakeState* state);
    NoiseDHState* noise_handshakestate_get_local_keypair_dh(const NoiseHandshakeState* state);
    size_t noise_dhstate_get_private_key_length(const NoiseDHState* state);
    int noise_dhstate_set_keypair_private(NoiseDHState* state,
        const uint8_t* private_key, size_t private_key_len);
    int noise_handshakestate_start(NoiseHandshakeState* state);
    int noise_handshakestate_write_message(NoiseHandshakeState* state,
        NoiseBuffer* message, const NoiseBuffer* payload);
    int noise_handshakestate_read_message(NoiseHandshakeState* state,
        NoiseBuffer* message, NoiseBuffer* payload);
    int noise_handshakestate_split(NoiseHandshakeState* state,
        NoiseCipherState** send, NoiseCipherState** receive);
    int noise_handshakestate_get_action(const NoiseHandshakeState* state);
    int noise_cipherstate_encrypt(NoiseCipherState* state, NoiseBuffer* buffer);
    int noise_cipherstate_decrypt(NoiseCipherState* state, NoiseBuffer* buffer);
    int noise_dhstate_get_public_key(const NoiseDHState* state,
        uint8_t* public_key, size_t public_key_len);
    NoiseDHState* noise_handshakestate_get_remote_public_key_dh(const NoiseHandshakeState* state);
    size_t noise_dhstate_get_public_key_length(const NoiseDHState* state);
    int noise_cipherstate_free(NoiseCipherState* state);
    int noise_init();
    int noise_dhstate_new_by_id(NoiseDHState** state, int id);
    int noise_dhstate_free(NoiseDHState* state);
    int noise_dhstate_generate_keypair(NoiseDHState* state);
    int noise_dhstate_get_keypair(const NoiseDHState* state,
        uint8_t* private_key, size_t private_key_len, uint8_t* public_key, size_t public_key_len);

    int noise_strerror(int err, char* buf, size_t size);

    enum NOISE_DH_CURVE25519 = NOISE_ID('D', 1);

    enum NOISE_ROLE_INITIATOR = NOISE_ID('R', 1);
    enum NOISE_ROLE_RESPONDER = NOISE_ID('R', 2);

    enum NOISE_ACTION_NONE = 0;
    enum NOISE_ACTION_WRITE_MESSAGE = NOISE_ID('A', 1);
    enum NOISE_ACTION_READ_MESSAGE = NOISE_ID('A', 2);
    enum NOISE_ACTION_FAILED = NOISE_ID('A', 3);
    enum NOISE_ACTION_SPLIT = NOISE_ID('A', 4);
    enum NOISE_ACTION_COMPLETE = NOISE_ID('A', 5);

    enum NOISE_ERROR_NONE = 0;
    enum NOISE_ERROR_NO_MEMORY = NOISE_ID('E', 1);
    enum NOISE_ERROR_UNKNOWN_ID = NOISE_ID('E', 2);
    enum NOISE_ERROR_UNKNOWN_NAME = NOISE_ID('E', 3);
    enum NOISE_ERROR_MAC_FAILURE = NOISE_ID('E', 4);
    enum NOISE_ERROR_NOT_APPLICABLE = NOISE_ID('E', 5);
    enum NOISE_ERROR_SYSTEM = NOISE_ID('E', 6);
    enum NOISE_ERROR_REMOTE_KEY_REQUIRED = NOISE_ID('E', 7);
    enum NOISE_ERROR_LOCAL_KEY_REQUIRED = NOISE_ID('E', 8);
    enum NOISE_ERROR_PSK_REQUIRED = NOISE_ID('E', 9);
    enum NOISE_ERROR_INVALID_LENGTH = NOISE_ID('E', 10);
    enum NOISE_ERROR_INVALID_PARAM = NOISE_ID('E', 11);
    enum NOISE_ERROR_INVALID_STATE = NOISE_ID('E', 12);
    enum NOISE_ERROR_INVALID_NONCE = NOISE_ID('E', 13);
    enum NOISE_ERROR_INVALID_PRIVATE_KEY = NOISE_ID('E', 14);
    enum NOISE_ERROR_INVALID_PUBLIC_KEY = NOISE_ID('E', 15);
    enum NOISE_ERROR_INVALID_FORMAT = NOISE_ID('E', 16);
    enum NOISE_ERROR_INVALID_SIGNATURE = NOISE_ID('E', 17);
}

void noise_buffer_init(ref NoiseBuffer buffer)
{
    buffer.data = null;
    buffer.size = 0;
    buffer.max_size = 0;
}

void noise_buffer_set_output(ref NoiseBuffer buffer, uint8_t* ptr, size_t len)
{
    buffer.data = ptr;
    buffer.size = 0;
    buffer.max_size = len;
}

void noise_buffer_set_input(ref NoiseBuffer buffer, uint8_t* ptr, size_t len)
{
    buffer.data = ptr;
    buffer.size = len;
    buffer.max_size = len;
}

void noise_buffer_set_inout(ref NoiseBuffer buffer, uint8_t* ptr, size_t len, size_t max)
{
    buffer.data = ptr;
    buffer.size = len;
    buffer.max_size = max;
}
