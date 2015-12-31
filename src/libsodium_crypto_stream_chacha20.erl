%% -*- mode: erlang; tab-width: 4; indent-tabs-mode: 1; st-rulers: [70] -*-
%% vim: ts=4 sw=4 ft=erlang noet
%%%-------------------------------------------------------------------
%%% @author Andrew Bennett <andrew@pixid.com>
%%% @copyright 2015-2016, Andrew Bennett
%%% @doc
%%%
%%% @end
%%% Created :  31 Dec 2015 by Andrew Bennett <andrew@pixid.com>
%%%-------------------------------------------------------------------
-module(libsodium_crypto_stream_chacha20).

-define(NAMESPACE, crypto_stream_chacha20).

%% API
-export([keybytes/0]).
-export([noncebytes/0]).
-export([crypto_stream_chacha20/3]).
-export(['xor'/3]).
-export([xor_ic/4]).
-export([ietf_noncebytes/0]).
-export([ietf/3]).
-export([ietf_xor/3]).
-export([ietf_xor_ic/4]).

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

crypto_stream_chacha20(CLen, N, K)
		when is_integer(CLen)
		andalso is_binary(N)
		andalso is_binary(K) ->
	call(crypto_stream_chacha20, {CLen, N, K}).

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

ietf_noncebytes() ->
	call(ietf_noncebytes).

ietf(CLen, N, K)
		when is_integer(CLen)
		andalso is_binary(N)
		andalso is_binary(K) ->
	call(ietf, {CLen, N, K}).

ietf_xor(M, N, K)
		when is_binary(M)
		andalso is_binary(N)
		andalso is_binary(K) ->
	call(ietf_xor, {M, N, K}).

ietf_xor_ic(M, N, IC, K)
		when is_binary(M)
		andalso is_binary(N)
		andalso is_integer(IC)
		andalso is_binary(K) ->
	call(ietf_xor_ic, {M, N, IC, K}).

%%%-------------------------------------------------------------------
%%% Internal functions
%%%-------------------------------------------------------------------

%% @private
call(Function) when is_atom(Function) ->
	call(Function, {}).

%% @private
call(Function, Arguments) when is_atom(Function) andalso is_tuple(Arguments) ->
	libsodium:call(?NAMESPACE, Function, Arguments).
