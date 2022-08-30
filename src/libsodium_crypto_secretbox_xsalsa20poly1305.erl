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
-module(libsodium_crypto_secretbox_xsalsa20poly1305).

-define(NAMESPACE, crypto_secretbox_xsalsa20poly1305).

%% API
-export([keybytes/0]).
-export([noncebytes/0]).
-export([macbytes/0]).
-export([messagebytes_max/0]).
-export([crypto_secretbox_xsalsa20poly1305/3]).
-export([open/3]).
-export([keygen/0]).
-export([zerobytes/0]).
-export([boxzerobytes/0]).


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

macbytes() ->
	call(macbytes).

messagebytes_max() ->
	call(messagebytes_max).

crypto_secretbox_xsalsa20poly1305(M, N, K)
		when is_binary(M)
		andalso is_binary(N)
		andalso is_binary(K) ->
	call(crypto_secretbox_xsalsa20poly1305, {M, N, K}).

open(C, N, K)
		when is_binary(C)
		andalso is_binary(N)
		andalso is_binary(K) ->
	call(open, {C, N, K}).

keygen() ->
	call(keygen).

zerobytes() ->
	call(zerobytes).

boxzerobytes() ->
	call(boxzerobytes).

%%%-------------------------------------------------------------------
%%% Internal functions
%%%-------------------------------------------------------------------

%% @private
call(Function) when is_atom(Function) ->
	call(Function, {}).

%% @private
call(Function, Arguments) when is_atom(Function) andalso is_tuple(Arguments) ->
	libsodium:call(?NAMESPACE, Function, Arguments).
