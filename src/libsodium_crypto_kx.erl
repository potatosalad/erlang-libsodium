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
-module(libsodium_crypto_kx).

-define(NAMESPACE, crypto_kx).

%% API
-export([publickeybytes/0]).
-export([secretkeybytes/0]).
-export([seedbytes/0]).
-export([sessionkeybytes/0]).
-export([primitive/0]).
-export([seed_keypair/1]).
-export([keypair/0]).
-export([client_session_keys/3]).
-export([server_session_keys/3]).

%% Internal API
-export([call/1]).
-export([call/2]).

%%%===================================================================
%%% API
%%%===================================================================

publickeybytes() ->
	call(publickeybytes).

secretkeybytes() ->
	call(secretkeybytes).

seedbytes() ->
	call(seedbytes).

sessionkeybytes() ->
	call(sessionkeybytes).

primitive() ->
	call(primitive).

seed_keypair(Seed)
		when is_binary(Seed) ->
	call(seed_keypair, {Seed}).

keypair() ->
	call(keypair).

client_session_keys(ClientPK, ClientSK, ServerPK)
		when is_binary(ClientPK)
		andalso is_binary(ClientSK)
		andalso is_binary(ServerPK) ->
	call(client_session_keys, {ClientPK, ClientSK, ServerPK}).

server_session_keys(ServerPK, ServerSK, ClientPK)
		when is_binary(ServerPK)
		andalso is_binary(ServerSK)
		andalso is_binary(ClientPK) ->
	call(server_session_keys, {ServerPK, ServerSK, ClientPK}).

%%%-------------------------------------------------------------------
%%% Internal functions
%%%-------------------------------------------------------------------

%% @private
call(Function) when is_atom(Function) ->
	call(Function, {}).

%% @private
call(Function, Arguments) when is_atom(Function) andalso is_tuple(Arguments) ->
	libsodium:call(?NAMESPACE, Function, Arguments).
