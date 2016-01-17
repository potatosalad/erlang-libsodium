%% -*- mode: erlang; tab-width: 4; indent-tabs-mode: 1; st-rulers: [70] -*-
%% vim: ts=4 sw=4 ft=erlang noet
%%%-------------------------------------------------------------------
%%% @author Andrew Bennett <andrew@pixid.com>
%%% @copyright 2015-2016, Andrew Bennett
%%% @doc
%%%
%%% @end
%%% Created :  14 Jan 2016 by Andrew Bennett <andrew@pixid.com>
%%%-------------------------------------------------------------------
-module(libsodium_SUITE).

-include_lib("common_test/include/ct.hrl").

%% ct.
-export([all/0]).
-export([groups/0]).
-export([init_per_suite/1]).
-export([end_per_suite/1]).
-export([init_per_group/2]).
-export([end_per_group/2]).

%% Tests.
-export([aead_aes256gcm/1]).
-export([aead_aes256gcm_checkbytes/1]).
-export([aead_chacha20poly1305/1]).
-export([aead_chacha20poly1305_checkbytes/1]).
-export([aead_chacha20poly1305_ietf/1]).
-export([sign/1]).

%% Macros.
-define(tv_ok(T, M, F, A, E),
	case erlang:apply(M, F, A) of
		E ->
			ok;
		T ->
			ct:fail({{M, F, A}, {expected, E}, {got, T}})
	end).

all() ->
	[
		{group, aead_aes256gcm},
		{group, aead_chacha20poly1305},
		{group, sign}
	].

groups() ->
	[
		{aead_aes256gcm, [parallel], [
			aead_aes256gcm,
			aead_aes256gcm_checkbytes
		]},
		{aead_chacha20poly1305, [parallel], [
			aead_chacha20poly1305,
			aead_chacha20poly1305_checkbytes,
			aead_chacha20poly1305_ietf
		]},
		{sign, [parallel], [
			sign
		]}
	].

init_per_suite(Config) ->
	_ = application:ensure_all_started(libsodium),
	Config.

end_per_suite(_Config) ->
	_ = application:stop(libsodium),
	ok.

init_per_group(aead_aes256gcm, Config) ->
	tv_file_hex("aead_aes256gcm.config", Config) ++ Config;
init_per_group(aead_chacha20poly1305, Config) ->
	tv_file("aead_chacha20poly1305.config", Config) ++ Config;
init_per_group(sign, Config) ->
	tv_file_hex("sign.config", Config) ++ Config.

end_per_group(_Group, _Config) ->
	ok.

%%====================================================================
%% Tests
%%====================================================================

aead_aes256gcm(Config) ->
	case libsodium_crypto_aead_aes256gcm:is_available() of
		1 ->
			Vectors = ?config(vectors, Config),
			aead_aes256gcm(Vectors, Config);
		_ ->
			ct:log("aead_aes256gcm is not available, skipping..."),
			ok
	end.

aead_aes256gcm_checkbytes(_Config) ->
	case libsodium_crypto_aead_aes256gcm:is_available() of
		1 ->
			checkbytes(libsodium_crypto_aead_aes256gcm, [
				{keybytes,    32},
				{nsecbytes,    0},
				{npubbytes,   12},
				{abytes,      16},
				{statebytes, 512}
			]);
		_ ->
			ct:log("aead_aes256gcm is not available, skipping..."),
			ok
	end.

aead_chacha20poly1305(Config) ->
	TV = ?config(tv, Config),
	aead_chacha20poly1305(TV, Config).

aead_chacha20poly1305_checkbytes(_Config) ->
	checkbytes(libsodium_crypto_aead_chacha20poly1305, [
		{keybytes,       32},
		{nsecbytes,       0},
		{npubbytes,       8},
		{abytes,         16},
		{ietf_npubbytes, 12}
	]).

aead_chacha20poly1305_ietf(Config) ->
	TVIETF = ?config(tv_ietf, Config),
	aead_chacha20poly1305_ietf(TVIETF, Config).

sign(Config) ->
	TV = ?config(tv, Config),
	sign(TV, Config).

%%%-------------------------------------------------------------------
%%% Internal Vector functions
%%%-------------------------------------------------------------------

%% @private
aead_aes256gcm([{Key, Nonce, Message, Ad, Ciphertext, Mac} | Vectors], Config) ->
	ExpectedCiphertext = << Ciphertext/binary, Mac/binary >>,
	TruncatedCiphertext = binary:part(ExpectedCiphertext, 0, libsodium_randombytes:uniform(byte_size(ExpectedCiphertext))),
	TruncatedTag = binary:part(ExpectedCiphertext, 0, libsodium_randombytes:uniform(libsodium_crypto_aead_aes256gcm:abytes())),
	?tv_ok(T0, libsodium_crypto_aead_aes256gcm, encrypt, [Message, Ad, Nonce, Key], ExpectedCiphertext),
	?tv_ok(T1, libsodium_crypto_aead_aes256gcm, decrypt, [TruncatedCiphertext, Ad, Nonce, Key], -1),
	?tv_ok(T2, libsodium_crypto_aead_aes256gcm, decrypt, [TruncatedTag, Ad, Nonce, Key], -1),
	?tv_ok(T3, libsodium_crypto_aead_aes256gcm, decrypt, [ExpectedCiphertext, Ad, Nonce, Key], Message),
	aead_aes256gcm(Vectors, Config);
aead_aes256gcm([], _Config) ->
	ok.

%% @private
aead_chacha20poly1305([{K, M, NPub, AD, C, CNoAD} | Vectors], Config) ->
	?tv_ok(T0, libsodium_crypto_aead_chacha20poly1305, encrypt, [M, AD, NPub, K], C),
	?tv_ok(T1, libsodium_crypto_aead_chacha20poly1305, encrypt, [M, NPub, K], CNoAD),
	?tv_ok(T2, libsodium_crypto_aead_chacha20poly1305, decrypt, [C, AD, NPub, K], M),
	?tv_ok(T3, libsodium_crypto_aead_chacha20poly1305, decrypt, [CNoAD, NPub, K], M),
	aead_chacha20poly1305(Vectors, Config);
aead_chacha20poly1305([], _Config) ->
	ok.

%% @private
aead_chacha20poly1305_ietf([{K, M, NPub, AD, C, CNoAD} | Vectors], Config) ->
	?tv_ok(T0, libsodium_crypto_aead_chacha20poly1305, ietf_encrypt, [M, AD, NPub, K], C),
	?tv_ok(T1, libsodium_crypto_aead_chacha20poly1305, ietf_encrypt, [M, NPub, K], CNoAD),
	?tv_ok(T2, libsodium_crypto_aead_chacha20poly1305, ietf_decrypt, [C, AD, NPub, K], M),
	?tv_ok(T3, libsodium_crypto_aead_chacha20poly1305, ietf_decrypt, [CNoAD, NPub, K], M),
	aead_chacha20poly1305_ietf(Vectors, Config);
aead_chacha20poly1305_ietf([], _Config) ->
	ok.

%% @private
sign([{Seed, PK, Sig, M} | Vectors], Config) ->
	SK = << Seed/binary, PK/binary >>,
	SM = << Sig/binary, M/binary >>,
	?tv_ok(T0, libsodium_crypto_sign, crypto_sign, [M, SK], SM),
	?tv_ok(T1, libsodium_crypto_sign, open, [SM, PK], M),
	?tv_ok(T2, libsodium_crypto_sign, detached, [M, SK], Sig),
	?tv_ok(T3, libsodium_crypto_sign, verify_detached, [Sig, M, PK], 0),
	sign(Vectors, Config);
sign([], _Config) ->
	ok.

%%%-------------------------------------------------------------------
%%% Internal functions
%%%-------------------------------------------------------------------

%% @private
checkbytes(Module, [{Function, Bytes} | Checks]) ->
	case Module:Function() of
		Bytes ->
			checkbytes(Module, Checks);
		Other ->
			ct:fail({{Module, Function, []}, {expected, Bytes}, {got, Other}})
	end;
checkbytes(_Module, []) ->
	ok.

%% @private
data_file(File, Config) ->
	filename:join([?config(data_dir, Config), File]).

%% @private
tv_file(Name, Config) ->
	File = data_file(Name, Config),
	case file:consult(File) of
		{ok, Terms} ->
			Terms;
		ConsultError ->
			erlang:error(ConsultError)
	end.

%% @private
tv_file_hex(Name, Config) ->
	[begin
		{Key, [begin
			list_to_tuple([hex:hex_to_bin(Val) || Val <- tuple_to_list(Tuple)])
		end || Tuple <- List, is_tuple(Tuple)]}
	end || {Key, List} <- tv_file(Name, Config), is_list(List)].
