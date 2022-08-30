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
-module(libsodium_crypto_scalarmult_ristretto255).

-define(NAMESPACE, crypto_scalarmult_ristretto255).

%% API
-export([bytes/0]).
-export([scalarbytes/0]).
-export([crypto_scalarmult_ristretto255/2]).
-export([base/1]).

%% Internal API
-export([call/1]).
-export([call/2]).

%%%===================================================================
%%% API
%%%===================================================================

bytes() ->
	call(bytes).

scalarbytes() ->
	call(scalarbytes).

crypto_scalarmult_ristretto255(N, P)
		when is_binary(N)
		andalso is_binary(P) ->
	call(crypto_scalarmult_ristretto255, {N, P}).


base(N)
		when is_binary(N) ->
	call(base, {N}).

%%%-------------------------------------------------------------------
%%% Internal functions
%%%-------------------------------------------------------------------

%% @private
call(Function) when is_atom(Function) ->
	call(Function, {}).

%% @private
call(Function, Arguments) when is_atom(Function) andalso is_tuple(Arguments) ->
	libsodium:call(?NAMESPACE, Function, Arguments).
