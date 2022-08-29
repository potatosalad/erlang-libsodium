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
-module(libsodium_crypto_stream_xchacha20).

-define(NAMESPACE, crypto_stream_xchacha20).

%% API
-export([keybytes/0]).
-export([noncebytes/0]).
-export([messagebytes_max/0]).
-export([crypto_stream_xchacha20/3]).
-export(['xor'/3]).
-export([xor_ic/4]).
-export([keygen/0]).

%% Internal API
-export([call/1]).
-export([call/2]).

%%%===================================================================
%%% API
%%%===================================================================

keybytes() ->
	call(keybytes).

noncebytes() ->
	call(noncebytes).

messagebytes_max() ->
	call(messagebytes_max).

crypto_stream_xchacha20(CLen, N, K)
		when is_integer(CLen)
		andalso is_binary(N)
		andalso is_binary(K) ->
	call(crypto_stream_xchacha20, {CLen, N, K}).

'xor'(M, N, K)
		when is_binary(M)
		andalso is_binary(N)
		andalso is_binary(K) ->
	call('xor', {M, N, K}).

xor_ic(M, N, IC, K)
		when is_binary(M)
		andalso is_binary(N)
		andalso is_integer(IC)
		andalso is_binary(K) ->
	call(xor_ic, {M, N, IC, K}).

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
