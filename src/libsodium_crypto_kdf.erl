%% -*- mode: erlang; tab-width: 4; indent-tabs-mode: 1; st-rulers: [70] -*-
%% vim: ts=4 sw=4 ft=erlang noet
%%%-------------------------------------------------------------------
%%% @author Andrew Bennett <potatosaladx@gmail.com>
%%% @copyright 2015-2022, Andrew Bennett
%%% @doc
%%%
%%% @end
%%% Created :  30 Aug 2022 by Andrew Bennett <potatosaladx@gmail.com>
%%%-------------------------------------------------------------------
-module(libsodium_crypto_kdf).

-define(NAMESPACE, crypto_kdf).

%% API
-export([bytes_min/0]).
-export([bytes_max/0]).
-export([contextbytes/0]).
-export([keybytes/0]).
-export([primitive/0]).
-export([derive_from_key/4]).
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

contextbytes() ->
	call(contextbytes).

keybytes() ->
	call(keybytes).

primitive() ->
	call(primitive).

derive_from_key(SubkeyLen, SubkeyId, Ctx, Key)
		when (is_integer(SubkeyLen) andalso SubkeyLen >= 0)
		andalso (is_integer(SubkeyId) andalso SubkeyId >= 0)
		andalso is_binary(Ctx)
		andalso is_binary(Key) ->
	call(derive_from_key, {SubkeyLen, SubkeyId, Ctx, Key}).

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
