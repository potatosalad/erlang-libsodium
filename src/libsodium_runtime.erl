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
-module(libsodium_runtime).

-define(NAMESPACE, runtime).

%% API
-export([has_neon/0]).
-export([has_sse2/0]).
-export([has_sse3/0]).
-export([has_ssse3/0]).
-export([has_sse41/0]).
-export([has_avx/0]).
-export([has_pclmul/0]).
-export([has_aesni/0]).

%% Internal API
-export([call/1]).
-export([call/2]).

%%%===================================================================
%%% API
%%%===================================================================

has_neon() ->
	call(has_neon).

has_sse2() ->
	call(has_sse2).

has_sse3() ->
	call(has_sse3).

has_ssse3() ->
	call(has_ssse3).

has_sse41() ->
	call(has_sse41).

has_avx() ->
	call(has_avx).

has_pclmul() ->
	call(has_pclmul).

has_aesni() ->
	call(has_aesni).

%%%-------------------------------------------------------------------
%%% Internal functions
%%%-------------------------------------------------------------------

%% @private
call(Function) when is_atom(Function) ->
	call(Function, {}).

%% @private
call(Function, Arguments) when is_atom(Function) andalso is_tuple(Arguments) ->
	libsodium:call(?NAMESPACE, Function, Arguments).
