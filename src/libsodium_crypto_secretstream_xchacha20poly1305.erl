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
-module(libsodium_crypto_secretstream_xchacha20poly1305).

-define(NAMESPACE, crypto_secretstream_xchacha20poly1305).

%% API
-export([abytes/0]).
-export([headerbytes/0]).
-export([keybytes/0]).
-export([messagebytes_max/0]).
-export([tag_message/0]).
-export([tag_push/0]).
-export([tag_rekey/0]).
-export([tag_final/0]).
-export([statebytes/0]).
-export([keygen/0]).
-export([init_push/1]).
-export([push/4]).
-export([init_pull/2]).
-export([pull/3]).
-export([rekey/1]).

%% Internal API
-export([call/1]).
-export([call/2]).

%%%===================================================================
%%% API
%%%===================================================================

abytes() ->
	call(abytes).

headerbytes() ->
	call(headerbytes).

keybytes() ->
	call(keybytes).

messagebytes_max() ->
	call(messagebytes_max).

tag_message() ->
	call(tag_message).

tag_push() ->
	call(tag_push).

tag_rekey() ->
	call(tag_rekey).

tag_final() ->
	call(tag_final).

statebytes() ->
	call(statebytes).

keygen() ->
	call(keygen).

init_push(K)
		when is_binary(K) ->
	call(init_push, {K}).

push(State, M, AD, Tag)
		when is_binary(State)
		andalso is_binary(M)
		andalso is_binary(AD)
		andalso (is_integer(Tag) andalso Tag >= 0) ->
	call(push, {State, M, AD, Tag}).

init_pull(Header, K)
		when is_binary(Header)
		andalso is_binary(K) ->
	call(init_pull, {Header, K}).

pull(State, C, AD)
		when is_binary(State)
		andalso is_binary(C)
		andalso is_binary(AD) ->
	call(pull, {State, C, AD}).

rekey(State)
		when is_binary(State) ->
	call(rekey, {State}).

%%%-------------------------------------------------------------------
%%% Internal functions
%%%-------------------------------------------------------------------

%% @private
call(Function) when is_atom(Function) ->
	call(Function, {}).

%% @private
call(Function, Arguments) when is_atom(Function) andalso is_tuple(Arguments) ->
	libsodium:call(?NAMESPACE, Function, Arguments).
