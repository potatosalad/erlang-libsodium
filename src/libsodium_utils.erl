%% -*- mode: erlang; tab-width: 4; indent-tabs-mode: 1; st-rulers: [70] -*-
%% vim: ts=4 sw=4 ft=erlang noet
%%%-------------------------------------------------------------------
%%% @author Andrew Bennett <andrew@pixid.com>
%%% @copyright 2015-2016, Andrew Bennett
%%% @doc
%%%
%%% @end
%%% Created :  30 Dec 2015 by Andrew Bennett <andrew@pixid.com>
%%%-------------------------------------------------------------------
-module(libsodium_utils).

-define(NAMESPACE, utils).

%% API
-export([compare/2]).
-export([is_zero/1]).
-export([increment/1]).
-export([add/2]).
-export([bin2hex/1]).
-export([hex2bin/1]).
-export([hex2bin/2]).

%% Internal API
-export([call/1]).
-export([call/2]).

%%%===================================================================
%%% API
%%%===================================================================

compare(B1, B2)
		when is_binary(B1)
		andalso is_binary(B2) ->
	call(compare, {B1, B2}).

is_zero(N)
		when is_binary(N) ->
	call(is_zero, {N}).

increment(N)
		when is_binary(N) ->
	call(increment, {N}).

add(A, B)
		when is_binary(A)
		andalso is_binary(B) ->
	call(add, {A, B}).

bin2hex(Bin)
		when is_binary(Bin) ->
	call(bin2hex, {Bin}).

hex2bin(Hex)
		when is_binary(Hex) ->
	hex2bin(Hex, <<>>).

hex2bin(Hex, Ignore)
		when is_binary(Hex)
		andalso is_binary(Ignore) ->
	call(hex2bin, {Hex, Ignore}).

%%%-------------------------------------------------------------------
%%% Internal functions
%%%-------------------------------------------------------------------

%% @private
call(Function) when is_atom(Function) ->
	call(Function, {}).

%% @private
call(Function, Arguments) when is_atom(Function) andalso is_tuple(Arguments) ->
	libsodium:call(?NAMESPACE, Function, Arguments).
