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
-module(libsodium_crypto_box_curve25519xchacha20poly1305).

-define(NAMESPACE, crypto_box_curve25519xchacha20poly1305).

%% API
-export([seedbytes/0]).
-export([publickeybytes/0]).
-export([secretkeybytes/0]).
-export([beforenmbytes/0]).
-export([noncebytes/0]).
-export([macbytes/0]).
-export([messagebytes_max/0]).
-export([seed_keypair/1]).
-export([keypair/0]).
-export([easy/4]).
-export([open_easy/4]).
-export([detached/4]).
-export([open_detached/5]).
-export([beforenm/2]).
-export([easy_afternm/3]).
-export([open_easy_afternm/3]).
-export([detached_afternm/3]).
-export([open_detached_afternm/4]).

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

macbytes() ->
	call(macbytes).

messagebytes_max() ->
	call(messagebytes_max).

seed_keypair(Seed)
		when is_binary(Seed) ->
	call(seed_keypair, {Seed}).

keypair() ->
	call(keypair).

easy(M, N, PK, SK)
		when is_binary(M)
		andalso is_binary(N)
		andalso is_binary(PK)
		andalso is_binary(SK) ->
	call(easy, {M, N, PK, SK}).

open_easy(C, N, PK, SK)
		when is_binary(C)
		andalso is_binary(N)
		andalso is_binary(PK)
		andalso is_binary(SK) ->
	call(open_easy, {C, N, PK, SK}).

detached(M, N, PK, SK)
		when is_binary(M)
		andalso is_binary(N)
		andalso is_binary(PK)
		andalso is_binary(SK) ->
	call(detached, {M, N, PK, SK}).

open_detached(C, MAC, N, PK, SK)
		when is_binary(C)
		andalso is_binary(MAC)
		andalso is_binary(N)
		andalso is_binary(PK)
		andalso is_binary(SK) ->
	call(open_detached, {C, MAC, N, PK, SK}).

beforenm(PK, SK)
		when is_binary(PK)
		andalso is_binary(SK) ->
	call(beforenm, {PK, SK}).

easy_afternm(M, N, K)
		when is_binary(M)
		andalso is_binary(N)
		andalso is_binary(K) ->
	call(easy_afternm, {M, N, K}).

open_easy_afternm(C, N, K)
		when is_binary(C)
		andalso is_binary(N)
		andalso is_binary(K) ->
	call(open_easy_afternm, {C, N, K}).

detached_afternm(M, N, K)
		when is_binary(M)
		andalso is_binary(N)
		andalso is_binary(K) ->
	call(detached_afternm, {M, N, K}).

open_detached_afternm(C, MAC, N, K)
		when is_binary(C)
		andalso is_binary(MAC)
		andalso is_binary(N)
		andalso is_binary(K) ->
	call(open_detached_afternm, {C, MAC, N, K}).

%%%-------------------------------------------------------------------
%%% Internal functions
%%%-------------------------------------------------------------------

%% @private
call(Function) when is_atom(Function) ->
	call(Function, {}).

%% @private
call(Function, Arguments) when is_atom(Function) andalso is_tuple(Arguments) ->
	libsodium:call(?NAMESPACE, Function, Arguments).
