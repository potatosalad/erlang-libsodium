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
-module(libsodium_crypto_box).

-define(NAMESPACE, crypto_box).

%% API
-export([seedbytes/0]).
-export([publickeybytes/0]).
-export([secretkeybytes/0]).
-export([noncebytes/0]).
-export([macbytes/0]).
-export([primitive/0]).
-export([seed_keypair/1]).
-export([keypair/0]).
-export([easy/4]).
-export([open_easy/4]).
-export([detached/4]).
-export([open_detached/5]).
-export([beforenmbytes/0]).
-export([beforenm/2]).
-export([easy_afternm/3]).
-export([open_easy_afternm/3]).
-export([detached_afternm/3]).
-export([open_detached_afternm/4]).
-export([sealbytes/0]).
-export([seal/2]).
-export([seal_open/3]).
-export([zerobytes/0]).
-export([boxzerobytes/0]).
-export([crypto_box/4]).
-export([open/4]).
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

noncebytes() ->
	call(noncebytes).

macbytes() ->
	call(macbytes).

primitive() ->
	call(primitive).

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

beforenmbytes() ->
	call(beforenmbytes).

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

sealbytes() ->
	call(sealbytes).

seal(M, PK)
		when is_binary(M)
		andalso is_binary(PK) ->
	call(seal, {M, PK}).

seal_open(C, PK, SK)
		when is_binary(C)
		andalso is_binary(PK)
		andalso is_binary(SK) ->
	call(seal_open, {C, PK, SK}).

zerobytes() ->
	call(zerobytes).

boxzerobytes() ->
	call(boxzerobytes).

crypto_box(M, N, PK, SK)
		when is_binary(M)
		andalso is_binary(N)
		andalso is_binary(PK)
		andalso is_binary(SK) ->
	call(crypto_box, {M, N, PK, SK}).

open(C, N, PK, SK)
		when is_binary(C)
		andalso is_binary(N)
		andalso is_binary(PK)
		andalso is_binary(SK) ->
	call(open, {C, N, PK, SK}).

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
