%% -*- mode: erlang; tab-width: 4; indent-tabs-mode: 1; st-rulers: [70] -*-
%% vim: ts=4 sw=4 ft=erlang noet
%%%-------------------------------------------------------------------
%%% @author Andrew Bennett <potatosaladx@gmail.com>
%%% @copyright 2015-2022, Andrew Bennett
%%% @doc
%%%
%%% @end
%%% Created :  30 Dec 2015 by Andrew Bennett <potatosaladx@gmail.com>
%%%-------------------------------------------------------------------
-module(libsodium_crypto_generichash_blake2b).

-define(NAMESPACE, crypto_generichash_blake2b).

%% API
-export([bytes_min/0]).
-export([bytes_max/0]).
-export([bytes/0]).
-export([keybytes_min/0]).
-export([keybytes_max/0]).
-export([keybytes/0]).
-export([saltbytes/0]).
-export([personalbytes/0]).
-export([statebytes/0]).
-export([crypto_generichash_blake2b/1]).
-export([crypto_generichash_blake2b/2]).
-export([crypto_generichash_blake2b/3]).
-export([salt_personal/3]).
-export([salt_personal/4]).
-export([salt_personal/5]).
-export([init/0]).
-export([init/1]).
-export([init/2]).
-export([init_salt_personal/2]).
-export([init_salt_personal/3]).
-export([init_salt_personal/4]).
-export([update/2]).
-export([final/1]).
-export([final/2]).
-export([keygen/0]).

%% Internal API
-export([call/1]).
-export([call/2]).

%%%===================================================================
%%% API
%%%===================================================================

bytes_min() ->
	call(bytes_min).

bytes_max() ->
	call(bytes_max).

bytes() ->
	call(bytes).

keybytes_min() ->
	call(keybytes_min).

keybytes_max() ->
	call(keybytes_max).

keybytes() ->
	call(keybytes).

saltbytes() ->
	call(saltbytes).

personalbytes() ->
	call(personalbytes).

statebytes() ->
	call(statebytes).

crypto_generichash_blake2b(In)
		when is_binary(In) ->
	crypto_generichash_blake2b(In, <<>>).

crypto_generichash_blake2b(In, Key)
		when is_binary(In)
		andalso is_binary(Key) ->
	crypto_generichash_blake2b(bytes(), In, Key).

crypto_generichash_blake2b(Outlen, In, Key)
		when is_integer(Outlen)
		andalso is_binary(In)
		andalso is_binary(Key) ->
	call(crypto_generichash_blake2b, {Outlen, In, Key}).

salt_personal(In, Salt, Personal)
		when is_binary(In)
		andalso is_binary(Salt)
		andalso is_binary(Personal) ->
	salt_personal(In, <<>>, Salt, Personal).

salt_personal(In, Key, Salt, Personal)
		when is_binary(In)
		andalso is_binary(Key)
		andalso is_binary(Salt)
		andalso is_binary(Personal) ->
	salt_personal(bytes(), In, Key, Salt, Personal).

salt_personal(Outlen, In, Key, Salt, Personal)
		when is_integer(Outlen)
		andalso is_binary(In)
		andalso is_binary(Key)
		andalso is_binary(Salt)
		andalso is_binary(Personal) ->
	call(salt_personal, {Outlen, In, Key, Salt, Personal}).

init() ->
	init(<<>>).

init(Key)
		when is_binary(Key) ->
	init(Key, bytes()).

init(Key, Outlen)
		when is_binary(Key)
		andalso is_integer(Outlen) ->
	call(init, {Key, Outlen}).

init_salt_personal(Salt, Personal)
	when is_binary(Salt)
	andalso is_binary(Personal) ->
	init_salt_personal(<<>>, Salt, Personal).

init_salt_personal(Key, Salt, Personal)
		when is_binary(Key)
		andalso is_binary(Salt)
		andalso is_binary(Personal) ->
	init_salt_personal(Key, bytes(), Salt, Personal).

init_salt_personal(Key, Outlen, Salt, Personal)
		when is_binary(Key)
		andalso is_integer(Outlen)
		andalso is_binary(Salt)
		andalso is_binary(Personal) ->
	call(init_salt_personal, {Key, Outlen, Salt, Personal}).

update(State, In)
		when is_binary(State)
		andalso is_binary(In) ->
	call(update, {State, In}).

final(State)
		when is_binary(State) ->
	final(State, bytes()).

final(State, Outlen)
		when is_binary(State)
		andalso is_integer(Outlen) ->
	call(final, {State, Outlen}).

keygen() ->
	call(keygen).

%%%-------------------------------------------------------------------
%%% Internal functions
%%%-------------------------------------------------------------------

%% @private
call(Function) when is_atom(Function) ->
	call(Function, {}).

%% @private
call(Function, Arguments) when is_atom(Function) andalso is_tuple(Arguments) ->
	libsodium:call(?NAMESPACE, Function, Arguments).
