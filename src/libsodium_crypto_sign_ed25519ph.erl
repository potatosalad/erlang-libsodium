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
-module(libsodium_crypto_sign_ed25519ph).

-define(NAMESPACE, crypto_sign_ed25519ph).

%% API
-export([statebytes/0]).
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
