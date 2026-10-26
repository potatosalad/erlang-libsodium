%%% % @format
-module(libsodium_sanitizer_stress).
-moduledoc """
Exercise native resource ownership, failure paths, and process cleanup under ASan.
""".
-moduledoc #{copyright => "Andrew Bennett"}.
-export([
    run/1
]).

run(Count) ->
    asan = erlang:system_info(emu_type),
    {ok, _} = application:ensure_all_started(libsodium),
    try batches(Count) after application:stop(libsodium) end,
    erlang:garbage_collect(),
    io:format("[sanitizers] completed ~B cleanup iterations~n", [Count]).

batches(0) ->
    ok;
batches(Remaining) ->
    Size = min(100, Remaining),
    {Pid, Ref} = spawn_monitor(fun() ->
        lists:foreach(fun iteration/1, lists:seq(Remaining - Size + 1, Remaining)),
        cancelled_update(),
        erlang:garbage_collect()
    end),
    receive
        {'DOWN', Ref, process, Pid, normal} -> batches(Remaining - Size);
        {'DOWN', Ref, process, Pid, Reason} -> error({stress_worker_failed, Reason})
    after 120000 ->
        exit(Pid, kill),
        error(stress_worker_timeout)
    end.

iteration(Index) ->
    %% Every hundredth input crosses the dirty threshold and the update chunk size.
    Input =
        case Index rem 100 of
            0 -> binary:copy(<<42>>, 200000);
            _ -> <<Index:64>>
        end,
    streaming(Input),
    aead(Index, Input),
    secretstream(Input),
    keccak(Index),
    outputs(Index, Input),
    errors(Index),
    ok.

%% Streaming states: every update and final copies a resource.
streaming(Input) ->
    Hash = libsodium_crypto_generichash,
    Digest = Hash:crypto_generichash(Input),
    State0 = Hash:init(),
    State1 = Hash:update(State0, Input),
    Digest = Hash:final(State1),
    Digest = Hash:final(Hash:update(State0, Input)),
    Sha = libsodium_crypto_hash_sha512,
    ShaDigest = Sha:crypto_hash_sha512(Input),
    ShaDigest = Sha:final(Sha:update(Sha:init(), Input)),
    Hmac = libsodium_crypto_auth_hmacsha256,
    Key = Hmac:keygen(),
    Tag = Hmac:crypto_auth_hmacsha256(Input, Key),
    Tag = Hmac:final(Hmac:update(Hmac:init(Key), Input)),
    Xof = libsodium_crypto_xof_shake256,
    {XofState, Out} = Xof:squeeze(Xof:update(Xof:init(), Input), 40),
    -1 = Xof:update(XofState, Input),
    Out = Xof:crypto_xof_shake256(40, Input),
    Sign = libsodium_crypto_sign_ed25519ph,
    {PK, SK} = libsodium_crypto_sign_ed25519:keypair(),
    Signed = Sign:update(Sign:init(), Input),
    Signature = Sign:final_create(Signed, SK),
    0 = Sign:final_verify(Signed, Signature, PK),
    Hkdf = libsodium_crypto_kdf_hkdf_sha256,
    PRK = Hkdf:extract(<<"salt">>, Input),
    PRK = Hkdf:extract_final(Hkdf:extract_update(Hkdf:extract_init(<<"salt">>), Input)),
    ok.

aead(Index, Input) ->
    Aead = libsodium_crypto_aead_xchacha20poly1305,
    Key = Aead:ietf_keygen(),
    Nonce = libsodium_randombytes:buf(Aead:ietf_npubbytes()),
    Ciphertext = Aead:ietf_encrypt(Input, <<Index:32>>, Nonce, Key),
    Input = Aead:ietf_decrypt(Ciphertext, <<Index:32>>, Nonce, Key),
    -1 = Aead:ietf_decrypt(Ciphertext, <<"wrong">>, Nonce, Key),
    %% Truncated ciphertexts shrink the output to zero bytes before failing.
    -1 = Aead:ietf_decrypt(binary:part(Ciphertext, 0, Index rem 16), <<>>, Nonce, Key),
    Gcm = libsodium_crypto_aead_aes256gcm,
    case Gcm:is_available() of
        1 ->
            GcmKey = Gcm:keygen(),
            GcmNonce = libsodium_randombytes:buf(Gcm:npubbytes()),
            Context = Gcm:beforenm(GcmKey),
            GcmCiphertext = Gcm:encrypt_afternm(Input, GcmNonce, Context),
            Input = Gcm:decrypt(GcmCiphertext, GcmNonce, GcmKey);
        0 ->
            ok
    end,
    ok.

secretstream(Input) ->
    Stream = libsodium_crypto_secretstream_xchacha20poly1305,
    Key = Stream:keygen(),
    {Push0, Header} = Stream:init_push(Key),
    {Push1, C1} = Stream:push(Push0, Input, <<>>, Stream:tag_message()),
    {_, C2} = Stream:push(Stream:rekey(Push1), Input, <<>>, Stream:tag_final()),
    Pull0 = Stream:init_pull(Header, Key),
    {Pull1, Input, 0} = Stream:pull(Pull0, C1, <<>>),
    {_, Input, 3} = Stream:pull(Stream:rekey(Pull1), C2, <<>>),
    -1 = Stream:pull(Pull0, C2, <<>>),
    ok.

keccak(Index) ->
    Keccak = libsodium_crypto_core_keccak1600,
    Offset = Index rem 200,
    Bytes = binary:copy(<<Index>>, 200 - Offset),
    State = Keccak:permute_12(Keccak:xor_bytes(Keccak:init(), Bytes, Offset)),
    <<_:(200 - Offset)/binary>> = Keccak:extract_bytes(State, Offset, 200 - Offset),
    badarg(fun() -> Keccak:extract_bytes(State, Offset, 201 - Offset) end).

%% Outputs whose final length is computed after the call, and so are shrunk.
outputs(Index, Input) ->
    Hex = libsodium_utils:bin2hex(Input),
    Input = libsodium_utils:hex2bin(<<Hex/binary, ":">>, <<":">>),
    Base64 = libsodium_utils:bin2base64(Input, urlsafe_no_padding),
    Input = libsodium_utils:base642bin(Base64, urlsafe_no_padding),
    Padded = libsodium_utils:pad(Input, 1 + Index rem 64),
    Input = libsodium_utils:unpad(Padded, 1 + Index rem 64),
    <<_:32/binary>> = libsodium_crypto_kdf:derive_from_key(32, Index, <<"Stresses">>, libsodium_crypto_kdf:keygen()),
    case Index rem 1000 of
        0 ->
            Pwhash = libsodium_crypto_pwhash,
            Str = Pwhash:str(<<"password">>, Pwhash:opslimit_min(), Pwhash:memlimit_min()),
            0 = Pwhash:str_verify(Str, <<"password">>),
            -1 = Pwhash:str_verify(Str, <<"wrong">>);
        _ ->
            ok
    end,
    ok.

%% Rejected arguments and mismatched states must release everything they decoded.
errors(Index) ->
    Sha256 = libsodium_crypto_hash_sha256:init(),
    badarg(fun() -> libsodium_crypto_hash_sha512:update(Sha256, <<Index:64>>) end),
    badarg(fun() -> libsodium_crypto_hash_sha512:final(Sha256) end),
    badarg(fun() -> libsodium_crypto_hash_sha256:update(<<0:832>>, <<>>) end),
    badarg(fun() -> libsodium_crypto_secretbox:easy(<<Index:64>>, <<0:8>>, <<0:256>>) end),
    badarg(fun() -> libsodium_crypto_pwhash:str_verify(<<"$argon2id", 0, "x">>, <<"password">>) end),
    badarg(fun() -> libsodium_utils:hex2bin(<<"00">>, <<":", 0>>) end),
    badarg(fun() -> libsodium_crypto_generichash:crypto_generichash(1, <<Index:64>>, <<>>) end),
    ok.

%% Killing a process mid-update must free the partially absorbed state.
cancelled_update() ->
    Large = binary:copy(<<7>>, 16 * 1024 * 1024),
    Init = libsodium_crypto_generichash:init(),
    {Pid, Ref} = spawn_monitor(fun() ->
        _ = libsodium_crypto_generichash:update(Init, Large),
        exit(finished)
    end),
    timer:sleep(1),
    exit(Pid, kill),
    receive
        {'DOWN', Ref, process, Pid, _} -> ok
    end.

badarg(Fun) ->
    try Fun() of
        Result -> error({expected_badarg, Result})
    catch
        error:badarg -> ok
    end.
