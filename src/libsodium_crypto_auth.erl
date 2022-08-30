%% -*- mode: erlang; tab-width: 4; indent-tabs-mode: 1; st-rulers: [70] -*-
%% vim: ts=4 sw=4 ft=erlang noet
%%%-------------------------------------------------------------------
%%% @author Andrew Bennett <potatosaladx@gmail.com>
%%% @copyright 2015-2022, Andrew Bennett
%%% @doc
%%%
%%% @end
%%% Created :  31 Dec 2015 by Andrew Bennett <potatosaladx@gmail.com>
%%%-------------------------------------------------------------------
-module(libsodium_crypto_auth).

-define(NAMESPACE, crypto_auth).

%% API
-export([bytes/0]).
-export([keybytes/0]).
-export([primitive/0]).
-export([crypto_auth/2]).
-export([verify/3]).
-export([keygen/0]).

%% Internal API
-export([call/1]).
-export([call/2]).

%%%===================================================================
%%% API
%%%===================================================================

bytes() ->
	call(bytes).

keybytes() ->
	call(keybytes).

primitive() ->
	call(primitive).

crypto_auth(In, K)
		when is_binary(In)
		andalso is_binary(K) ->
	call(crypto_auth, {In, K}).

verify(H, In, K)
		when is_binary(H)
		andalso is_binary(In)
		andalso is_binary(K) ->
	call(verify, {H, In, K}).

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
