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
-module(libsodium_crypto_onetimeauth_poly1305).

-define(NAMESPACE, crypto_onetimeauth_poly1305).

%% API
-export([bytes/0]).
-export([keybytes/0]).
-export([crypto_onetimeauth_poly1305/2]).
-export([verify/3]).
-export([init/1]).
-export([update/2]).
-export([final/1]).

%% Internal API
-export([call/1]).
-export([call/2]).

%%%===================================================================
%%% API
%%%===================================================================

bytes() ->
	call(bytes).

keybytes() ->
	call(keybytes).

crypto_onetimeauth_poly1305(In, K)
		when is_binary(In)
		andalso is_binary(K) ->
	call(crypto_onetimeauth_poly1305, {In, K}).

verify(H, In, K)
		when is_binary(H)
		andalso is_binary(In)
		andalso is_binary(K) ->
	call(verify, {H, In, K}).

init(Key)
		when is_binary(Key) ->
	call(init, {Key}).

update(State, In)
		when is_binary(State)
		andalso is_binary(In) ->
	call(update, {State, In}).

final(State)
		when is_binary(State) ->
	call(final, {State}).

%%%-------------------------------------------------------------------
%%% Internal functions
%%%-------------------------------------------------------------------

%% @private
call(Function) when is_atom(Function) ->
	call(Function, {}).

%% @private
call(Function, Arguments) when is_atom(Function) andalso is_tuple(Arguments) ->
	libsodium:call(?NAMESPACE, Function, Arguments).
