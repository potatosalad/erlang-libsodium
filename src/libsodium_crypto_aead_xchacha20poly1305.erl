%% -*- mode: erlang; tab-width: 4; indent-tabs-mode: 1; st-rulers: [70] -*-
%% vim: ts=4 sw=4 ft=erlang noet
%%%-------------------------------------------------------------------
%%% @author Andrew Bennett <potatosaladx@gmail.com>
%%% @copyright 2015-2022, Andrew Bennett
%%% @doc
%%%
%%% @end
%%% Created :  29 Aug 2022 by Andrew Bennett <potatosaladx@gmail.com>
%%%-------------------------------------------------------------------
-module(libsodium_crypto_aead_xchacha20poly1305).

-define(NAMESPACE, crypto_aead_xchacha20poly1305).

%% API
-export([ietf_keybytes/0]).
-export([ietf_nsecbytes/0]).
-export([ietf_npubbytes/0]).
-export([ietf_abytes/0]).
-export([ietf_messagebytes_max/0]).
-export([ietf_encrypt/3]).
-export([ietf_encrypt/4]).
-export([ietf_decrypt/3]).
-export([ietf_decrypt/4]).
-export([ietf_encrypt_detached/3]).
-export([ietf_encrypt_detached/4]).
-export([ietf_decrypt_detached/4]).
-export([ietf_decrypt_detached/5]).
-export([ietf_keygen/0]).

%% Internal API
-export([call/1]).
-export([call/2]).

%%%===================================================================
%%% API
%%%===================================================================

ietf_keybytes() ->
	call(ietf_keybytes).

ietf_nsecbytes() ->
	call(ietf_nsecbytes).

ietf_npubbytes() ->
	call(ietf_npubbytes).

ietf_abytes() ->
	call(ietf_abytes).

ietf_messagebytes_max() ->
	call(ietf_messagebytes_max).

ietf_encrypt(M, NPub, K)
		when is_binary(M)
		andalso is_binary(NPub)
		andalso is_binary(K) ->
	ietf_encrypt(M, <<>>, NPub, K).

ietf_encrypt(M, AD, NPub, K)
		when is_binary(M)
		andalso is_binary(AD)
		andalso is_binary(NPub)
		andalso is_binary(K) ->
	call(ietf_encrypt, {M, AD, <<>>, NPub, K}).

ietf_decrypt(C, NPub, K)
		when is_binary(C)
		andalso is_binary(NPub)
		andalso is_binary(K) ->
	ietf_decrypt(C, <<>>, NPub, K).

ietf_decrypt(C, AD, NPub, K)
		when is_binary(C)
		andalso is_binary(AD)
		andalso is_binary(NPub)
		andalso is_binary(K) ->
	call(ietf_decrypt, {<<>>, C, AD, NPub, K}).

ietf_encrypt_detached(M, NPub, K)
		when is_binary(M)
		andalso is_binary(NPub)
		andalso is_binary(K) ->
	ietf_encrypt_detached(M, <<>>, NPub, K).

ietf_encrypt_detached(M, AD, NPub, K)
		when is_binary(M)
		andalso is_binary(AD)
		andalso is_binary(NPub)
		andalso is_binary(K) ->
	call(ietf_encrypt_detached, {M, AD, <<>>, NPub, K}).

ietf_decrypt_detached(C, MAC, NPub, K)
		when is_binary(C)
		andalso is_binary(MAC)
		andalso is_binary(NPub)
		andalso is_binary(K) ->
	ietf_decrypt_detached(C, MAC, <<>>, NPub, K).

ietf_decrypt_detached(C, MAC, AD, NPub, K)
		when is_binary(C)
		andalso is_binary(MAC)
		andalso is_binary(AD)
		andalso is_binary(NPub)
		andalso is_binary(K) ->
	call(ietf_decrypt_detached, {<<>>, C, MAC, AD, NPub, K}).

ietf_keygen() ->
	call(ietf_keygen).

%%%-------------------------------------------------------------------
%%% Internal functions
%%%-------------------------------------------------------------------

%% @private
call(Function) when is_atom(Function) ->
	call(Function, {}).

%% @private
call(Function, Arguments) when is_atom(Function) andalso is_tuple(Arguments) ->
	libsodium:call(?NAMESPACE, Function, Arguments).
