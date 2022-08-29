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
-module(libsodium_crypto_hash_sha256).

-define(NAMESPACE, crypto_hash_sha256).

%% API
-export([statebytes/0]).
-export([bytes/0]).
-export([crypto_hash_sha256/1]).
-export([init/0]).
-export([update/2]).
-export([final/1]).

%% Internal API
-export([call/1]).
-export([call/2]).

%%%===================================================================
%%% API
%%%===================================================================

statebytes() ->
	call(statebytes).

bytes() ->
	call(bytes).

crypto_hash_sha256(In)
		when is_binary(In) ->
	call(crypto_hash_sha256, {In}).

init() ->
	call(init).

update(State, In)
		when is_binary(State)
		andalso is_binary(In) ->
	call(update, {State, In}).

final(State)
		when is_binary(State) ->
	call(final, {State}).

%%%-------------------------------------------------------------------
%%% Internal functions
%%%-------------------------------------------------------------------

%% @private
call(Function) when is_atom(Function) ->
	call(Function, {}).

%% @private
call(Function, Arguments) when is_atom(Function) andalso is_tuple(Arguments) ->
	libsodium:call(?NAMESPACE, Function, Arguments).
