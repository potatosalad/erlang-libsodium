%% -*- mode: erlang; tab-width: 4; indent-tabs-mode: 1; st-rulers: [70] -*-
%% vim: ts=4 sw=4 ft=erlang noet
%%%-------------------------------------------------------------------
%%% @author Andrew Bennett <potatosaladx@gmail.com>
%%% @copyright 2015-2022, Andrew Bennett
%%% @doc
%%%
%%% @end
%%% Created :  29 Aug 2022 by Andrew Bennett <potatosaladx@gmail.com>
%%%-------------------------------------------------------------------
-module(libsodium_crypto_core_ed25519).

-define(NAMESPACE, crypto_core_ed25519).

%% API
-export([bytes/0]).
-export([uniformbytes/0]).
-export([hashbytes/0]).
-export([scalarbytes/0]).
-export([nonreducedscalarbytes/0]).
-export([is_valid_point/1]).
-export([add/2]).
-export([sub/2]).
-export([from_uniform/1]).
-export([from_hash/1]).
-export([random/0]).
-export([scalar_random/0]).
-export([scalar_invert/1]).
-export([scalar_negate/1]).
-export([scalar_complement/1]).
-export([scalar_add/2]).
-export([scalar_sub/2]).
-export([scalar_mul/2]).
-export([scalar_reduce/1]).

%% Internal API
-export([call/1]).
-export([call/2]).

%%%===================================================================
%%% API
%%%===================================================================

bytes() ->
	call(bytes).

uniformbytes() ->
	call(uniformbytes).

hashbytes() ->
	call(hashbytes).

scalarbytes() ->
	call(scalarbytes).

nonreducedscalarbytes() ->
	call(nonreducedscalarbytes).

is_valid_point(P)
		when is_binary(P) ->
	call(is_valid_point, {P}).

add(P, Q)
		when is_binary(P)
		andalso is_binary(Q) ->
	call(add, {P, Q}).

sub(P, Q)
		when is_binary(P)
		andalso is_binary(Q) ->
	call(sub, {P, Q}).

from_uniform(R)
		when is_binary(R) ->
	call(from_uniform, {R}).

from_hash(H)
		when is_binary(H) ->
	call(from_hash, {H}).

random() ->
	call(random).

scalar_random() ->
	call(scalar_random).

scalar_invert(S)
		when is_binary(S) ->
	call(scalar_invert, {S}).

scalar_negate(S)
		when is_binary(S) ->
	call(scalar_negate, {S}).

scalar_complement(S)
		when is_binary(S) ->
	call(scalar_complement, {S}).

scalar_add(X, Y)
		when is_binary(X)
		andalso is_binary(Y) ->
	call(scalar_add, {X, Y}).

scalar_sub(X, Y)
		when is_binary(X)
		andalso is_binary(Y) ->
	call(scalar_sub, {X, Y}).

scalar_mul(X, Y)
		when is_binary(X)
		andalso is_binary(Y) ->
	call(scalar_mul, {X, Y}).

scalar_reduce(S)
		when is_binary(S) ->
	call(scalar_reduce, {S}).

%%%-------------------------------------------------------------------
%%% Internal functions
%%%-------------------------------------------------------------------

%% @private
call(Function) when is_atom(Function) ->
	call(Function, {}).

%% @private
call(Function, Arguments) when is_atom(Function) andalso is_tuple(Arguments) ->
	libsodium:call(?NAMESPACE, Function, Arguments).
