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
-module(libsodium_crypto_sign).

-define(NAMESPACE, crypto_sign).

%% API
-export([bytes/0]).
-export([seedbytes/0]).
-export([publickeybytes/0]).
-export([secretkeybytes/0]).
-export([primitive/0]).
-export([seed_keypair/1]).
-export([keypair/0]).
-export([crypto_sign/2]).
-export([open/2]).
-export([detached/2]).
-export([verify_detached/3]).

%% Internal API
-export([call/1]).
-export([call/2]).

%%%===================================================================
%%% API
%%%===================================================================

bytes() ->
	call(bytes).

seedbytes() ->
	call(seedbytes).

publickeybytes() ->
	call(publickeybytes).

secretkeybytes() ->
	call(secretkeybytes).

primitive() ->
	call(primitive).

seed_keypair(Seed)
		when is_binary(Seed) ->
	call(seed_keypair, {Seed}).

keypair() ->
	call(keypair).

crypto_sign(M, SK)
		when is_binary(M)
		andalso is_binary(SK) ->
	call(crypto_sign, {M, SK}).

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

%%%-------------------------------------------------------------------
%%% Internal functions
%%%-------------------------------------------------------------------

%% @private
call(Function) when is_atom(Function) ->
	call(Function, {}).

%% @private
call(Function, Arguments) when is_atom(Function) andalso is_tuple(Arguments) ->
	libsodium:call(?NAMESPACE, Function, Arguments).
