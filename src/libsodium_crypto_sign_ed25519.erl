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
-module(libsodium_crypto_sign_ed25519).

-define(NAMESPACE, crypto_sign_ed25519).

%% API
-export([statebytes/0]).
-export([bytes/0]).
-export([seedbytes/0]).
-export([publickeybytes/0]).
-export([secretkeybytes/0]).
-export([messagebytes_max/0]).
-export([crypto_sign_ed25519/2]).
-export([open/2]).
-export([detached/2]).
-export([verify_detached/3]).
-export([keypair/0]).
-export([seed_keypair/1]).
-export([pk_to_curve25519/1]).
-export([sk_to_curve25519/1]).
-export([sk_to_seed/1]).
-export([sk_to_pk/1]).
-export([init/0]).
-export([update/2]).
-export([final_create/2]).
-export([final_verify/3]).

%% Internal API
-export([call/1]).
-export([call/2]).

%%%===================================================================
%%% API
%%%===================================================================

statebytes() ->
	call(statebytes).

bytes() ->
	call(bytes).

seedbytes() ->
	call(seedbytes).

publickeybytes() ->
	call(publickeybytes).

secretkeybytes() ->
	call(secretkeybytes).

messagebytes_max() ->
	call(messagebytes_max).

crypto_sign_ed25519(M, SK)
		when is_binary(M)
		andalso is_binary(SK) ->
	call(crypto_sign_ed25519, {M, SK}).

open(SM, PK)
		when is_binary(SM)
		andalso is_binary(PK) ->
	call(open, {SM, PK}).

detached(M, SK)
		when is_binary(M)
		andalso is_binary(SK) ->
	call(detached, {M, SK}).

verify_detached(Sig, M, PK)
		when is_binary(Sig)
		andalso is_binary(M)
		andalso is_binary(PK) ->
	call(verify_detached, {Sig, M, PK}).

keypair() ->
	call(keypair).

seed_keypair(Seed)
		when is_binary(Seed) ->
	call(seed_keypair, {Seed}).

pk_to_curve25519(Ed25519PK)
		when is_binary(Ed25519PK) ->
	call(pk_to_curve25519, {Ed25519PK}).

sk_to_curve25519(Ed25519SK)
		when is_binary(Ed25519SK) ->
	call(sk_to_curve25519, {Ed25519SK}).

sk_to_seed(SK)
		when is_binary(SK) ->
	call(sk_to_seed, {SK}).

sk_to_pk(SK)
		when is_binary(SK) ->
	call(sk_to_pk, {SK}).

init() ->
	call(init).

update(State, M)
		when is_binary(State)
		andalso is_binary(M) ->
	call(update, {State, M}).

final_create(State, SK)
		when is_binary(State)
		andalso is_binary(SK) ->
	call(final_create, {State, SK}).

final_verify(State, Sig, PK)
		when is_binary(State)
		andalso is_binary(Sig)
		andalso is_binary(PK) ->
	call(final_verify, {State, Sig, PK}).

%%%-------------------------------------------------------------------
%%% Internal functions
%%%-------------------------------------------------------------------

%% @private
call(Function) when is_atom(Function) ->
	call(Function, {}).

%% @private
call(Function, Arguments) when is_atom(Function) andalso is_tuple(Arguments) ->
	libsodium:call(?NAMESPACE, Function, Arguments).
