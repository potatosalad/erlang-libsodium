%%% % @format
-module(libsodium_SUITE).
-compile(warn_missing_spec_all).
-moduledoc """
Common Test coverage for libsodium's published test vectors.

Covers AEAD constructions, sealed boxes, password hashing, and Ed25519
signatures, including truncated inputs and invalid parameters.
""".
-moduledoc #{author => ["Andrew Bennett <potatosaladx@gmail.com>"]}.
-moduledoc #{created => "2016-01-14", modified => "2026-10-26"}.
-moduledoc #{copyright => "Andrew Bennett"}.

-include_lib("common_test/include/ct.hrl").

%% The legacy dispatch shim is tested on purpose.
-compile({nowarn_deprecated_function, [{libsodium, call, 2}, {libsodium, call, 3}]}).

%% Vector files mix strings, binaries, and integers.
-eqwalizer({nowarn_function, hex_value/1}).

%% ct.
-export([
    all/0,
    groups/0,
    init_per_suite/1,
    end_per_suite/1,
    init_per_group/2,
    end_per_group/2
]).

%% Tests.
-export([
    aead_aes256gcm/1,
    aead_aes256gcm_check/1,
    aead_chacha20poly1305/1,
    aead_chacha20poly1305_check/1,
    aead_chacha20poly1305_ietf/1,
    box_check/1,
    box_seal/1,
    legacy_call/1,
    state_resources/1,
    pwhash_argon2i_key_derivation/1,
    pwhash_argon2i_password_storage/1,
    pwhash_argon2id_key_derivation/1,
    pwhash_argon2id_password_storage/1,
    pwhash_scrypt_key_derivation/1,
    pwhash_scrypt_password_storage/1,
    sign/1
]).

-spec all() -> Result when Result :: [ct_suite:ct_test_def()].
all() ->
    [
        {group, aead_aes256gcm},
        {group, aead_chacha20poly1305},
        {group, box},
        legacy_call,
        state_resources,
        {group, pwhash_argon2i},
        {group, pwhash_argon2id},
        {group, pwhash_scrypt},
        {group, sign}
    ].

-spec groups() -> Result when Result :: [ct_suite:ct_group_def()].
groups() ->
    [
        {aead_aes256gcm, [parallel], [
            aead_aes256gcm,
            aead_aes256gcm_check
        ]},
        {aead_chacha20poly1305, [parallel], [
            aead_chacha20poly1305,
            aead_chacha20poly1305_check,
            aead_chacha20poly1305_ietf
        ]},
        {box, [parallel], [
            box_check,
            box_seal
        ]},
        {pwhash_argon2i, [parallel], [
            pwhash_argon2i_key_derivation,
            pwhash_argon2i_password_storage
        ]},
        {pwhash_argon2id, [parallel], [
            pwhash_argon2id_key_derivation,
            pwhash_argon2id_password_storage
        ]},
        {pwhash_scrypt, [parallel], [
            pwhash_scrypt_key_derivation,
            pwhash_scrypt_password_storage
        ]},
        {sign, [parallel], [
            sign
        ]}
    ].

-spec init_per_suite(Config) -> Result when Config :: ct_suite:ct_config(), Result :: ct_suite:ct_config().
init_per_suite(Config) ->
    {ok, _} = application:ensure_all_started(libsodium),
    Config.

-spec end_per_suite(Config) -> Result when Config :: ct_suite:ct_config(), Result :: ok.
end_per_suite(_Config) ->
    _ = application:stop(libsodium),
    ok.

-spec init_per_group(Group, Config) -> Result when
    Group :: atom(), Config :: ct_suite:ct_config(), Result :: ct_suite:ct_config().
init_per_group(Group, Config) ->
    init_group(Group, libsodium_ct:start(Group, Config)).

-spec init_group(Group, Config) -> Result when
    Group :: atom(), Config :: ct_suite:ct_config(), Result :: ct_suite:ct_config().
init_group(aead_aes256gcm, Config) ->
    tv_file_hex("aead_aes256gcm.config", Config) ++ Config;
init_group(aead_chacha20poly1305, Config) ->
    tv_file("aead_chacha20poly1305.config", Config) ++ Config;
init_group(pwhash_argon2i, Config) ->
    tv_file_hex("pwhash_argon2i.config", Config) ++ Config;
init_group(pwhash_argon2id, Config) ->
    tv_file_hex("pwhash_argon2id.config", Config) ++ Config;
init_group(pwhash_scrypt, Config) ->
    tv_file_hex("pwhash_scrypt.config", Config) ++ Config;
init_group(sign, Config) ->
    tv_file_hex("sign.config", Config) ++ Config;
init_group(_, Config) ->
    Config.

-spec end_per_group(Group, Config) -> Result when Group :: atom(), Config :: ct_suite:ct_config(), Result :: ok.
end_per_group(_Group, Config) ->
    libsodium_ct:stop(Config).

%%%=============================================================================
%%% Tests
%%%=============================================================================

-spec aead_aes256gcm(Config) -> Result when Config :: ct_suite:ct_config(), Result :: ok | {skip, string()}.
aead_aes256gcm(Config) ->
    case libsodium_crypto_aead_aes256gcm:is_available() of
        1 ->
            aead_aes256gcm_vectors(?config(vectors, Config));
        _ ->
            {skip, "AES256-GCM is not available on this CPU"}
    end.

-spec aead_aes256gcm_check(Config) -> Result when Config :: ct_suite:ct_config(), Result :: ok.
aead_aes256gcm_check(_Config) ->
    check(libsodium_crypto_aead_aes256gcm, [
        {keybytes, 32},
        {nsecbytes, 0},
        {npubbytes, 12},
        {abytes, 16},
        {statebytes, 512}
    ]).

-spec aead_chacha20poly1305(Config) -> Result when Config :: ct_suite:ct_config(), Result :: ok.
aead_chacha20poly1305(Config) ->
    aead_chacha20poly1305_vectors(?config(tv, Config), "").

-spec aead_chacha20poly1305_check(Config) -> Result when Config :: ct_suite:ct_config(), Result :: ok.
aead_chacha20poly1305_check(_Config) ->
    check(libsodium_crypto_aead_chacha20poly1305, [
        {keybytes, 32},
        {nsecbytes, 0},
        {npubbytes, 8},
        {abytes, 16},
        {ietf_npubbytes, 12}
    ]).

-spec aead_chacha20poly1305_ietf(Config) -> Result when Config :: ct_suite:ct_config(), Result :: ok.
aead_chacha20poly1305_ietf(Config) ->
    aead_chacha20poly1305_vectors(?config(tv_ietf, Config), "ietf_").

-spec box_check(Config) -> Result when Config :: ct_suite:ct_config(), Result :: ok.
box_check(_Config) ->
    check(libsodium_crypto_box, [
        {seedbytes, 32},
        {publickeybytes, 32},
        {secretkeybytes, 32},
        {noncebytes, 24},
        {macbytes, 16},
        {primitive, curve25519xsalsa20poly1305},
        {beforenmbytes, 32},
        {sealbytes, 48},
        {zerobytes, 32},
        {boxzerobytes, 16}
    ]).

-spec box_seal(Config) -> Result when Config :: ct_suite:ct_config(), Result :: ok.
box_seal(_Config) ->
    {PK, SK} = libsodium_crypto_box:keypair(),
    MLen = libsodium_randombytes:uniform(1000),
    M = libsodium_randombytes:buf(MLen),
    C = binary_value(tv_not(libsodium_crypto_box, seal, [M, PK], -1)),
    CLen = libsodium_crypto_box:sealbytes() + MLen,
    CLen = byte_size(C),
    ok = tv_ok(libsodium_crypto_box, seal_open, [C, PK, SK], M),
    ok = libsodium_ct:assert_badarg(libsodium_crypto_box, seal_open, [<<>>, PK, SK]),
    tv_ok(libsodium_crypto_box, seal_open, [binary:part(C, 0, CLen - 1), PK, SK], -1).

-spec legacy_call(Config) -> Result when Config :: ct_suite:ct_config(), Result :: ok.
legacy_call(_Config) ->
    32 = libsodium:call(crypto_box, seedbytes),
    {PK, SK} = libsodium:call(crypto_box, seed_keypair, {binary:copy(<<1>>, 32)}),
    {PK, SK} = libsodium_crypto_box:seed_keypair(binary:copy(<<1>>, 32)),
    ok = libsodium_ct:assert_badarg(libsodium, call, [crypto_box, seed_keypair, {<<>>}]),
    try libsodium:call(crypto_box, no_such_function, {}) of
        Result -> ct:fail({expected_undef, Result})
    catch
        error:undef -> ok
    end.

-spec state_resources(Config) -> Result when Config :: ct_suite:ct_config(), Result :: ok.
state_resources(_Config) ->
    Sha256 = libsodium_crypto_hash_sha256,
    Init = Sha256:init(),
    true = is_reference(Init),
    %% States are immutable: updating twice from the same state gives the same result.
    State1 = Sha256:update(Init, <<"abc">>),
    State2 = Sha256:update(Init, <<"abc">>),
    Digest = crypto:hash(sha256, <<"abc">>),
    Digest = Sha256:final(State1),
    Digest = Sha256:final(State2),
    Digest = Sha256:final(State1),
    %% Finishing one state leaves the others usable.
    Digest = Sha256:crypto_hash_sha256(<<"abc">>),
    <<_:256>> = Sha256:final(Init),
    %% States are only accepted by the API that created them.
    ok = libsodium_ct:assert_badarg(libsodium_crypto_hash_sha512, update, [Init, <<"abc">>]),
    ok = libsodium_ct:assert_badarg(libsodium_crypto_hash_sha512, final, [Init]),
    ok = libsodium_ct:assert_badarg(Sha256, update, [binary:copy(<<0>>, Sha256:statebytes()), <<"abc">>]),
    %% States can be shared between processes.
    Parent = self(),
    _ = spawn_link(fun() -> Parent ! {state, Sha256:final(State1)} end),
    receive
        {state, Digest} -> ok
    after 5000 -> ct:fail(state_not_shared)
    end.

-spec pwhash_argon2i_key_derivation(Config) -> Result when Config :: ct_suite:ct_config(), Result :: ok.
pwhash_argon2i_key_derivation(Config) ->
    pwhash_argon2_key_derivation(libsodium_crypto_pwhash_argon2i, crypto_pwhash_argon2i, ?config(tv, Config)).

-spec pwhash_argon2i_password_storage(Config) -> Result when Config :: ct_suite:ct_config(), Result :: ok.
pwhash_argon2i_password_storage(Config) ->
    pwhash_password_storage(libsodium_crypto_pwhash_argon2i, ?config(tv3, Config), 3, 5000000).

-spec pwhash_argon2id_key_derivation(Config) -> Result when Config :: ct_suite:ct_config(), Result :: ok.
pwhash_argon2id_key_derivation(Config) ->
    pwhash_argon2_key_derivation(libsodium_crypto_pwhash_argon2id, crypto_pwhash_argon2id, ?config(tv, Config)).

-spec pwhash_argon2id_password_storage(Config) -> Result when Config :: ct_suite:ct_config(), Result :: ok.
pwhash_argon2id_password_storage(Config) ->
    pwhash_password_storage(libsodium_crypto_pwhash_argon2id, ?config(tv3, Config), 3, 5000000).

-spec pwhash_scrypt_key_derivation(Config) -> Result when Config :: ct_suite:ct_config(), Result :: ok.
pwhash_scrypt_key_derivation(Config) ->
    lists:foreach(
        fun({Passwd, _Passwdlen, Salt, Outlen, Opslimit, Memlimit, Out}) ->
            ok = tv_ok(
                libsodium_crypto_pwhash_scryptsalsa208sha256,
                crypto_pwhash_scryptsalsa208sha256,
                [Outlen, Passwd, Salt, Opslimit, Memlimit],
                Out
            )
        end,
        ?config(tv, Config)
    ).

-spec pwhash_scrypt_password_storage(Config) -> Result when Config :: ct_suite:ct_config(), Result :: ok.
pwhash_scrypt_password_storage(Config) ->
    pwhash_password_storage(libsodium_crypto_pwhash_scryptsalsa208sha256, ?config(tv3, Config), 1000000, 10000000).

-spec sign(Config) -> Result when Config :: ct_suite:ct_config(), Result :: ok.
sign(Config) ->
    lists:foreach(
        fun({Seed, PK, Sig, M}) ->
            SK = <<Seed/binary, PK/binary>>,
            SM = <<Sig/binary, M/binary>>,
            ok = tv_ok(libsodium_crypto_sign, crypto_sign, [M, SK], SM),
            ok = tv_ok(libsodium_crypto_sign, open, [SM, PK], M),
            ok = tv_ok(libsodium_crypto_sign, detached, [M, SK], Sig),
            ok = tv_ok(libsodium_crypto_sign, verify_detached, [Sig, M, PK], 0)
        end,
        ?config(tv, Config)
    ).

%%%-----------------------------------------------------------------------------
%%% Internal vector functions
%%%-----------------------------------------------------------------------------

-spec aead_aes256gcm_vectors(Vectors) -> Result when Vectors :: [tuple()], Result :: ok.
aead_aes256gcm_vectors(Vectors) ->
    M = libsodium_crypto_aead_aes256gcm,
    lists:foreach(
        fun({Key, Nonce, Message, Ad, Ciphertext0, Mac0}) ->
            Ciphertext = binary_value(Ciphertext0),
            Mac = binary_value(Mac0),
            Expected = <<Ciphertext/binary, Mac/binary>>,
            TruncatedCiphertext = truncate(Expected),
            TruncatedTag = binary:part(Expected, 0, libsodium_randombytes:uniform(M:abytes())),
            TruncatedMac = truncate(Mac),
            ok = tv_ok(M, encrypt, [Message, Ad, Nonce, Key], Expected),
            ok = tv_ok(M, decrypt, [TruncatedCiphertext, Ad, Nonce, Key], -1),
            ok = tv_ok(M, decrypt, [TruncatedTag, Ad, Nonce, Key], -1),
            ok = tv_ok(M, decrypt, [Expected, Ad, Nonce, Key], Message),
            ok = tv_ok(M, encrypt_detached, [Message, Ad, Nonce, Key], {Ciphertext, Mac}),
            ok = libsodium_ct:assert_badarg(M, decrypt_detached, [Ciphertext, TruncatedMac, Ad, Nonce, Key]),
            ok = tv_ok(M, decrypt_detached, [Ciphertext, Mac, Ad, Nonce, Key], Message)
        end,
        Vectors
    ).

-spec aead_chacha20poly1305_vectors(Vectors, Prefix) -> Result when
    Vectors :: [tuple()], Prefix :: string(), Result :: ok.
aead_chacha20poly1305_vectors(Vectors, Prefix) ->
    M = libsodium_crypto_aead_chacha20poly1305,
    F = fun(Name) -> list_to_atom(Prefix ++ Name) end,
    lists:foreach(
        fun({K, Message0, NPub, AD, C0, CNoAD}) ->
            Message = binary_value(Message0),
            C = binary_value(C0),
            MLen = byte_size(Message),
            <<CD:MLen/binary, MAC/binary>> = C,
            ok = tv_ok(M, F("encrypt"), [Message, AD, NPub, K], C),
            ok = tv_ok(M, F("encrypt"), [Message, NPub, K], CNoAD),
            ok = tv_ok(M, F("decrypt"), [C, AD, NPub, K], Message),
            ok = tv_ok(M, F("decrypt"), [CNoAD, NPub, K], Message),
            ok = tv_ok(M, F("decrypt"), [truncate(C), AD, NPub, K], -1),
            ok = tv_ok(M, F("encrypt_detached"), [Message, AD, NPub, K], {CD, MAC}),
            ok = libsodium_ct:assert_badarg(M, F("decrypt_detached"), [CD, truncate(MAC), AD, NPub, K]),
            ok = tv_ok(M, F("decrypt_detached"), [CD, MAC, AD, NPub, K], Message)
        end,
        Vectors
    ).

-spec pwhash_argon2_key_derivation(Module, Function, Vectors) -> Result when
    Module :: module(), Function :: atom(), Vectors :: [tuple()], Result :: ok.
pwhash_argon2_key_derivation(Module, Function, Vectors) ->
    Default = libsodium_crypto_pwhash:alg_default(),
    lists:foreach(
        fun
            ({Passwd, _Passwdlen, Salt, Outlen, Opslimit, Memlimit, Alg, Out}) ->
                ok = tv_ok(Module, Function, [Outlen, Passwd, Salt, Opslimit, Memlimit, Alg], Out);
            ({Passwd, _Passwdlen, Salt, Outlen}) ->
                ok = tv_ok(Module, Function, [Outlen, Passwd, Salt, 3, 1 bsl 12, 0], -1),
                ok = tv_ok(Module, Function, [Outlen, Passwd, Salt, 3, 1, Default], -1),
                ok = tv_ok(Module, Function, [Outlen, Passwd, Salt, 3, 1 bsl 12, Default], -1),
                ok = tv_ok(Module, Function, [Outlen, Passwd, Salt, 2, 1 bsl 12, Default], -1)
        end,
        Vectors
    ).

-spec pwhash_password_storage(Module, Vectors, Opslimit, Memlimit) -> Result when
    Module :: module(), Vectors :: [tuple()], Opslimit :: pos_integer(), Memlimit :: pos_integer(), Result :: ok.
pwhash_password_storage(Module, Vectors, Opslimit, Memlimit) ->
    lists:foreach(
        fun({Passwd, Out, Verified}) ->
            ok = tv_ok(Module, str_verify, [Out, Passwd], Verified)
        end,
        Vectors
    ),
    Passwd = <<"Correct Horse Battery Staple">>,
    Hash1 = tv_not(Module, str, [Passwd, Opslimit, Memlimit], -1),
    Hash2 = tv_not(Module, str, [Passwd, Opslimit, Memlimit], Hash1),
    ok = tv_ok(Module, str_verify, [Hash1, Passwd], 0),
    tv_ok(Module, str_verify, [Hash2, Passwd], 0).

%%%-----------------------------------------------------------------------------
%%% Internal functions
%%%-----------------------------------------------------------------------------

-spec tv_ok(Module, Function, Arguments, Expected) -> Result when
    Module :: module(), Function :: atom(), Arguments :: [term()], Expected :: term(), Result :: ok.
tv_ok(Module, Function, Arguments, Expected) ->
    case libsodium_ct:call(Module, Function, Arguments) of
        Expected ->
            ok;
        Result ->
            ct:fail({{Module, Function, Arguments}, {expected, Expected}, {got, Result}})
    end.

-spec tv_not(Module, Function, Arguments, Unexpected) -> Result when
    Module :: module(), Function :: atom(), Arguments :: [term()], Unexpected :: term(), Result :: term().
tv_not(Module, Function, Arguments, Unexpected) ->
    case libsodium_ct:call(Module, Function, Arguments) of
        Unexpected ->
            ct:fail({{Module, Function, Arguments}, {not_expected, Unexpected}});
        Result ->
            Result
    end.

-spec check(Module, Checks) -> Result when Module :: module(), Checks :: [{atom(), term()}], Result :: ok.
check(Module, Checks) ->
    lists:foreach(fun({Function, Value}) -> ok = tv_ok(Module, Function, [], Value) end, Checks).

-spec binary_value(Term) -> Binary when Term :: term(), Binary :: binary().
binary_value(Binary) when is_binary(Binary) ->
    Binary;
binary_value(Term) ->
    ct:fail({expected_binary, Term}).

-spec truncate(Binary) -> Truncated when Binary :: binary(), Truncated :: binary().
truncate(Binary) ->
    binary:part(Binary, 0, libsodium_randombytes:uniform(byte_size(Binary))).

-spec tv_file(Name, Config) -> Result when
    Name :: file:filename(), Config :: ct_suite:ct_config(), Result :: [{atom(), [tuple()]}].
tv_file(Name, Config) ->
    File = filename:join([?config(data_dir, Config), Name]),
    case file:consult(File) of
        {ok, Terms} ->
            Terms;
        ConsultError ->
            erlang:error(ConsultError)
    end.

-spec tv_file_hex(Name, Config) -> Result when
    Name :: file:filename(), Config :: ct_suite:ct_config(), Result :: [{atom(), [tuple()]}].
tv_file_hex(Name, Config) ->
    [
        {Key, [list_to_tuple([hex_value(Value) || Value <- tuple_to_list(Tuple)]) || Tuple <- List, is_tuple(Tuple)]}
     || {Key, List} <- tv_file(Name, Config), is_list(List)
    ].

-spec hex_value(Value) -> Result when Value :: term(), Result :: term().
hex_value(Value) when is_list(Value) ->
    hex_value(list_to_binary(Value));
hex_value(Value) when is_binary(Value) ->
    try
        binary:decode_hex(Value)
    catch
        error:badarg ->
            Value
    end;
hex_value(Value) ->
    Value.
