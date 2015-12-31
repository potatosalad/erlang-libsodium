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
-module(libsodium_crypto_stream_aes128ctr).

-define(NAMESPACE, crypto_stream_aes128ctr).

%% API
-export([keybytes/0]).
-export([noncebytes/0]).
-export([beforenmbytes/0]).
-export([crypto_stream_aes128ctr/3]).
-export(['xor'/3]).
-export([beforenm/1]).
-export([afternm/3]).
-export([xor_afternm/3]).

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

beforenmbytes() ->
	call(beforenmbytes).

crypto_stream_aes128ctr(Outlen, N, K)
		when is_integer(Outlen)
		andalso is_binary(N)
		andalso is_binary(K) ->
	call(crypto_stream_aes128ctr, {Outlen, N, K}).

'xor'(In, N, K)
		when is_binary(In)
		andalso is_binary(N)
		andalso is_binary(K) ->
	call('xor', {In, N, K}).

beforenm(K)
		when is_binary(K) ->
	call(beforenm, {K}).

afternm(Len, Nonce, C)
		when is_integer(Len)
		andalso is_binary(Nonce)
		andalso is_binary(C) ->
	call(afternm, {Len, Nonce, C}).

xor_afternm(In, Nonce, C)
		when is_binary(In)
		andalso is_binary(Nonce)
		andalso is_binary(C) ->
	call(xor_afternm, {In, Nonce, C}).

%%%-------------------------------------------------------------------
%%% Internal functions
%%%-------------------------------------------------------------------

%% @private
call(Function) when is_atom(Function) ->
	call(Function, {}).

%% @private
call(Function, Arguments) when is_atom(Function) andalso is_tuple(Arguments) ->
	libsodium:call(?NAMESPACE, Function, Arguments).
