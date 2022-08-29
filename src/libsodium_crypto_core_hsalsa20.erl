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
-module(libsodium_crypto_core_hsalsa20).

-define(NAMESPACE, crypto_core_hsalsa20).

%% API
-export([outputbytes/0]).
-export([inputbytes/0]).
-export([keybytes/0]).
-export([constbytes/0]).
-export([crypto_core_hsalsa20/3]).

%% Internal API
-export([call/1]).
-export([call/2]).

%%%===================================================================
%%% API
%%%===================================================================

outputbytes() ->
	call(outputbytes).

inputbytes() ->
	call(inputbytes).

keybytes() ->
	call(keybytes).

constbytes() ->
	call(constbytes).

crypto_core_hsalsa20(In, K, C)
		when is_binary(In)
		andalso is_binary(K)
		andalso is_binary(C) ->
	call(crypto_core_hsalsa20, {In, K, C}).

%%%-------------------------------------------------------------------
%%% Internal functions
%%%-------------------------------------------------------------------

%% @private
call(Function) when is_atom(Function) ->
	call(Function, {}).

%% @private
call(Function, Arguments) when is_atom(Function) andalso is_tuple(Arguments) ->
	libsodium:call(?NAMESPACE, Function, Arguments).
