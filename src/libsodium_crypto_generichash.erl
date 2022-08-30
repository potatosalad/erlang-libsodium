%% -*- mode: erlang; tab-width: 4; indent-tabs-mode: 1; st-rulers: [70] -*-
%% vim: ts=4 sw=4 ft=erlang noet
%%%-------------------------------------------------------------------
%%% @author Andrew Bennett <potatosaladx@gmail.com>
%%% @copyright 2015-2022, Andrew Bennett
%%% @doc
%%%
%%% @end
%%% Created :  30 Dec 2015 by Andrew Bennett <potatosaladx@gmail.com>
%%%-------------------------------------------------------------------
-module(libsodium_crypto_generichash).

-define(NAMESPACE, crypto_generichash).

%% API
-export([bytes_min/0]).
-export([bytes_max/0]).
-export([bytes/0]).
-export([keybytes_min/0]).
-export([keybytes_max/0]).
-export([keybytes/0]).
-export([primitive/0]).
-export([statebytes/0]).
-export([crypto_generichash/1]).
-export([crypto_generichash/2]).
-export([crypto_generichash/3]).
-export([init/0]).
-export([init/1]).
-export([init/2]).
-export([update/2]).
-export([final/1]).
-export([final/2]).
-export([keygen/0]).

%% Internal API
-export([call/1]).
-export([call/2]).

%%%===================================================================
%%% API
%%%===================================================================

bytes_min() ->
	call(bytes_min).

bytes_max() ->
	call(bytes_max).

bytes() ->
	call(bytes).

keybytes_min() ->
	call(keybytes_min).

keybytes_max() ->
	call(keybytes_max).

keybytes() ->
	call(keybytes).

primitive() ->
	call(primitive).

statebytes() ->
	call(statebytes).

crypto_generichash(In)
		when is_binary(In) ->
	crypto_generichash(In, <<>>).

crypto_generichash(In, Key)
		when is_binary(In)
		andalso is_binary(Key) ->
	crypto_generichash(bytes(), In, Key).

crypto_generichash(Outlen, In, Key)
		when is_integer(Outlen)
		andalso is_binary(In)
		andalso is_binary(Key) ->
	call(crypto_generichash, {Outlen, In, Key}).

init() ->
	init(<<>>).

init(Key)
		when is_binary(Key) ->
	init(Key, bytes()).

init(Key, Outlen)
		when is_binary(Key)
		andalso is_integer(Outlen) ->
	call(init, {Key, Outlen}).

update(State, In)
		when is_binary(State)
		andalso is_binary(In) ->
	call(update, {State, In}).

final(State)
		when is_binary(State) ->
	final(State, bytes()).

final(State, Outlen)
		when is_binary(State)
		andalso is_integer(Outlen) ->
	call(final, {State, Outlen}).

keygen() ->
	call(keygen).

%%%-------------------------------------------------------------------
%%% Internal functions
%%%-------------------------------------------------------------------

%% @private
call(Function) when is_atom(Function) ->
	call(Function, {}).

%% @private
call(Function, Arguments) when is_atom(Function) andalso is_tuple(Arguments) ->
	libsodium:call(?NAMESPACE, Function, Arguments).
