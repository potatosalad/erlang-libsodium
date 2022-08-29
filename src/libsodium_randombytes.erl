%% -*- mode: erlang; tab-width: 4; indent-tabs-mode: 1; st-rulers: [70] -*-
%% vim: ts=4 sw=4 ft=erlang noet
%%%-------------------------------------------------------------------
%%% @author Andrew Bennett <potatosaladx@gmail.com>
%%% @copyright 2015-2022, Andrew Bennett
%%% @doc
%%%
%%% @end
%%% Created :  29 Dec 2015 by Andrew Bennett <potatosaladx@gmail.com>
%%%-------------------------------------------------------------------
-module(libsodium_randombytes).

-define(NAMESPACE, randombytes).

%% API
-export([seedbytes/0]).
-export([buf/1]).
-export([random/0]).
-export([uniform/1]).
-export([stir/0]).
-export([close/0]).
-export([set_implementation/1]).
-export([implementation_name/0]).
-export([randombytes/1]). % NaCl compatibility interface

%% Internal API
-export([call/1]).
-export([call/2]).

%%%===================================================================
%%% API
%%%===================================================================

seedbytes() ->
	call(seedbytes).

buf(Size)
		when is_integer(Size)
		andalso Size >= 0 ->
	call(buf, {Size}).

random() ->
	call(random).

uniform(UpperBound)
		when UpperBound >= 0
		andalso UpperBound < 16#FFFFFFFF ->
	call(uniform, {UpperBound}).

stir() ->
	call(stir).

close() ->
	call(close).

set_implementation(Impl)
		when is_atom(Impl) ->
	call(set_implementation, {Impl}).

implementation_name() ->
	call(implementation_name).

randombytes(Size)
		when is_integer(Size)
		andalso Size >= 0 ->
	call(randombytes, {Size}).

%%%-------------------------------------------------------------------
%%% Internal functions
%%%-------------------------------------------------------------------

%% @private
call(Function) when is_atom(Function) ->
	call(Function, {}).

%% @private
call(Function, Arguments) when is_atom(Function) andalso is_tuple(Arguments) ->
	libsodium:call(?NAMESPACE, Function, Arguments).
