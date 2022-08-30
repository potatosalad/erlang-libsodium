%% -*- mode: erlang; tab-width: 4; indent-tabs-mode: 1; st-rulers: [70] -*-
%% vim: ts=4 sw=4 ft=erlang noet
%%%-------------------------------------------------------------------
%%% @author Andrew Bennett <potatosaladx@gmail.com>
%%% @copyright 2015-2022, Andrew Bennett
%%% @doc
%%%
%%% @end
%%% Created :  14 Jan 2016 by Andrew Bennett <potatosaladx@gmail.com>
%%%-------------------------------------------------------------------
-module(libsodium_crypto_box_curve25519xsalsa20poly1305).

-define(NAMESPACE, crypto_box_curve25519xsalsa20poly1305).

%% API
-export([seedbytes/0]).
-export([publickeybytes/0]).
-export([secretkeybytes/0]).
-export([beforenmbytes/0]).
-export([noncebytes/0]).
-export([zerobytes/0]).
-export([boxzerobytes/0]).
-export([macbytes/0]).
-export([messagebytes_max/0]).
-export([crypto_box_curve25519xsalsa20poly1305/4]).
-export([open/4]).
-export([seed_keypair/1]).
-export([keypair/0]).
-export([beforenm/2]).
-export([afternm/3]).
-export([open_afternm/3]).

%% Internal API
-export([call/1]).
-export([call/2]).

%%%===================================================================
%%% API
%%%===================================================================

seedbytes() ->
	call(seedbytes).

publickeybytes() ->
	call(publickeybytes).

secretkeybytes() ->
	call(secretkeybytes).

beforenmbytes() ->
	call(beforenmbytes).

noncebytes() ->
	call(noncebytes).

zerobytes() ->
	call(zerobytes).

boxzerobytes() ->
	call(boxzerobytes).

macbytes() ->
	call(macbytes).

messagebytes_max() ->
	call(messagebytes_max).

crypto_box_curve25519xsalsa20poly1305(M, N, PK, SK)
		when is_binary(M)
		andalso is_binary(N)
		andalso is_binary(PK)
		andalso is_binary(SK) ->
	call(crypto_box_curve25519xsalsa20poly1305, {M, N, PK, SK}).

open(C, N, PK, SK)
		when is_binary(C)
		andalso is_binary(N)
		andalso is_binary(PK)
		andalso is_binary(SK) ->
	call(open, {C, N, PK, SK}).

seed_keypair(Seed)
		when is_binary(Seed) ->
	call(seed_keypair, {Seed}).

keypair() ->
	call(keypair).

beforenm(PK, SK)
		when is_binary(PK)
		andalso is_binary(SK) ->
	call(beforenm, {PK, SK}).

afternm(M, N, K)
		when is_binary(M)
		andalso is_binary(N)
		andalso is_binary(K) ->
	call(afternm, {M, N, K}).

open_afternm(C, N, K)
		when is_binary(C)
		andalso is_binary(N)
		andalso is_binary(K) ->
	call(open_afternm, {C, N, K}).

%%%-------------------------------------------------------------------
%%% Internal functions
%%%-------------------------------------------------------------------

%% @private
call(Function) when is_atom(Function) ->
	call(Function, {}).

%% @private
call(Function, Arguments) when is_atom(Function) andalso is_tuple(Arguments) ->
	libsodium:call(?NAMESPACE, Function, Arguments).
